import { describe, expect, it, vi } from "vitest";

import { requestContextToJson, type RequestContext } from "../src/audit.js";
import { AuthzDeniedError, AuthzStateError } from "../src/errors.js";
import { createAuthKit } from "../src/index.js";
import type { Row } from "../src/query.js";
import { createReadApi } from "../src/reads.js";
import type { AuthzFunction, AuthzTransport, RpcArgs } from "../src/transport.js";
import { createWriteApi } from "../src/writes.js";

const ACTOR = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const ROLE = "33333333-3333-4333-8333-333333333333";
const PRINCIPAL = "44444444-4444-4444-8444-444444444444";
const BINDING = "55555555-5555-4555-8555-555555555555";

const CONTEXT: RequestContext = {
    requestId: "req-1",
    method: "POST",
    route: "/tenants/:id/members",
    ip: "203.0.113.7",
    userAgent: "curl/8",
};

/** Records every call, and fails whichever function the test names. */
function stubTransport(
    failing?: { fn: AuthzFunction; error: unknown },
): AuthzTransport & { calls: [string, RpcArgs][] } {
    const calls: [string, RpcArgs][] = [];

    return {
        calls,
        scalar: async (fn, args) => {
            calls.push([fn, args]);

            if (failing?.fn === fn) {
                throw failing.error;
            }

            return "ok";
        },
        rows: async (fn, args) => {
            calls.push([fn, args]);

            return [] as Row[];
        },
    };
}

describe("requestContextToJson", () => {
    it("maps to the snake_case keys SQL reads", () => {
        expect(requestContextToJson(CONTEXT)).toEqual({
            request_id: "req-1",
            method: "POST",
            route: "/tenants/:id/members",
            ip: "203.0.113.7",
            user_agent: "curl/8",
        });
    });

    it("is undefined when there is nothing to say, so the columns stay null", () => {
        // Undefined rather than {}: both transports omit an undefined argument, which lets the
        // SQL default apply. An empty object would read as "there was a request we know
        // nothing about", which is a different claim.
        expect(requestContextToJson(null)).toBeUndefined();
        expect(requestContextToJson(undefined)).toBeUndefined();
        expect(requestContextToJson({})).toBeUndefined();
    });

    it("omits absent fields rather than sending nulls", () => {
        expect(requestContextToJson({ method: "GET" })).toEqual({ method: "GET" });
    });
});

describe("request context on writes", () => {
    it("travels with every mutating call", async () => {
        const transport = stubTransport();

        await createWriteApi(transport, ACTOR, { requestContext: CONTEXT }).createRole(
            TENANT,
            "editor",
            "Edits",
        );

        expect(transport.calls[0]?.[1]).toMatchObject({
            p_actor_principal_id: ACTOR,
            p_request_ctx: { request_id: "req-1", method: "POST" },
        });
    });

    it("is omitted entirely when the caller has none", async () => {
        const transport = stubTransport();

        await createWriteApi(transport, ACTOR).createRole(TENANT, "editor", "Edits");

        // Omitted, not null: the SQL default applies either way, but an explicit null would
        // make a future default impossible to introduce.
        expect(transport.calls[0]?.[1]["p_request_ctx"]).toBeUndefined();
    });
});

describe("denial logging", () => {
    const denied = new AuthzDeniedError(
        "principal lacks authz.roles.write at tenant",
        "P0001",
    );

    it("records a denied row and rethrows the original refusal", async () => {
        const transport = stubTransport({ fn: "create_role", error: denied });
        const api = createWriteApi(transport, ACTOR, { requestContext: CONTEXT });

        await expect(api.createRole(TENANT, "editor", "Edits")).rejects.toBe(denied);

        expect(transport.calls.map(([fn]) => fn)).toEqual(["create_role", "log_audit"]);
        expect(transport.calls[1]?.[1]).toMatchObject({
            p_actor_principal_id: ACTOR,
            p_tenant_id: TENANT,
            p_action: "create_role",
            p_target_type: "role",
            p_outcome: "denied",
            p_reason: "principal lacks authz.roles.write at tenant",
        });
    });

    it("anchors the row on the tenant the arguments name", async () => {
        const transport = stubTransport({ fn: "grant_role", error: denied });

        await expect(
            createWriteApi(transport, ACTOR).grantRole(PRINCIPAL, ROLE, TENANT),
        ).rejects.toBe(denied);

        expect(transport.calls[1]?.[1]).toMatchObject({
            p_tenant_id: TENANT,
            p_target_type: "role_binding",
        });
    });

    it("records no tenant where only the row being changed knows it", async () => {
        const transport = stubTransport({ fn: "revoke_binding", error: denied });

        await expect(
            createWriteApi(transport, ACTOR).revokeBinding(BINDING),
        ).rejects.toBe(denied);

        // A platform-level row: revoke_binding is anchored on the binding's own tenant, which
        // TypeScript would have to query for -- a second chance to fail on the denial path.
        expect(transport.calls[1]?.[1]).toMatchObject({
            p_tenant_id: null,
            p_target_type: "role_binding",
            p_target_id: BINDING,
        });
    });

    it("keeps the invited address out of the denied row", async () => {
        const transport = stubTransport({ fn: "invite_user", error: denied });

        await expect(
            createWriteApi(transport, ACTOR).inviteUser(TENANT, "someone@example.com", ROLE),
        ).rejects.toBe(denied);

        // The refusal may be the retired-identity probe invite_user orders its checks to
        // prevent; writing the address into a readable table would hand back what that
        // ordering protects.
        expect(JSON.stringify(transport.calls[1]?.[1])).not.toContain("someone@example.com");
    });

    it("logs nothing for a failure that is not a refusal", async () => {
        const error = new AuthzStateError("bootstrap has not run", "P0002");
        const transport = stubTransport({ fn: "create_role", error });

        await expect(
            createWriteApi(transport, ACTOR).createRole(TENANT, "editor", "Edits"),
        ).rejects.toBe(error);

        expect(transport.calls.map(([fn]) => fn)).toEqual(["create_role"]);
    });

    it("is off when audit.denials is false", async () => {
        const transport = stubTransport({ fn: "create_role", error: denied });

        await expect(
            createWriteApi(transport, ACTOR, { auditDenials: false }).createRole(
                TENANT,
                "editor",
                "Edits",
            ),
        ).rejects.toBe(denied);

        expect(transport.calls.map(([fn]) => fn)).toEqual(["create_role"]);
    });

    it("never lets a logging failure mask the refusal", async () => {
        const logFailure = new Error("audit insert failed");
        const transport: AuthzTransport = {
            scalar: async fn => {
                if (fn === "create_role") throw denied;
                throw logFailure;
            },
            rows: async () => [],
        };

        const onError = vi.fn();

        await expect(
            createWriteApi(transport, ACTOR, { onAuditError: onError }).createRole(
                TENANT,
                "editor",
                "Edits",
            ),
        ).rejects.toBe(denied);

        // Reported, not swallowed silently -- but reported somewhere that cannot change what
        // the caller sees.
        expect(onError).toHaveBeenCalledWith(logFailure);
    });
});

describe("logAudit", () => {
    it("binds the actor and the request, like every other call", async () => {
        const transport = stubTransport();

        await createWriteApi(transport, ACTOR, { requestContext: CONTEXT }).logAudit({
            tenantId: TENANT,
            action: "invoice.deleted",
            targetType: "invoice",
            targetId: ROLE,
            before: { total: 100 },
        });

        expect(transport.calls[0]).toEqual([
            "log_audit",
            {
                p_actor_principal_id: ACTOR,
                p_tenant_id: TENANT,
                p_action: "invoice.deleted",
                p_target_type: "invoice",
                p_target_id: ROLE,
                p_before: { total: 100 },
                p_after: null,
                p_outcome: "success",
                p_reason: null,
                p_request_ctx: requestContextToJson(CONTEXT),
            },
        ]);
    });

    it("resolves null instead of rejecting when the write fails", async () => {
        const transport = stubTransport({
            fn: "log_audit",
            error: new Error("connection reset"),
        });

        const onError = vi.fn();

        await expect(
            createWriteApi(transport, ACTOR, { onAuditError: onError }).logAudit({
                action: "invoice.deleted",
                targetType: "invoice",
            }),
        ).resolves.toBeNull();

        expect(onError).toHaveBeenCalledOnce();
    });
});

describe("pruneAuditLogs", () => {
    function kitWith(rows: Row[]) {
        const calls: [string, RpcArgs][] = [];

        const transport: AuthzTransport = {
            scalar: async () => null,
            rows: async (fn, args) => {
                calls.push([fn, args]);

                return rows;
            },
        };

        return { kit: createAuthKit({ transport, verifyBearer: async () => null }), calls };
    }

    it("lives on the kit, not on an actor", () => {
        const { kit } = kitWith([]);

        // No principal does this: the SQL function has no actor parameter at all.
        expect(typeof kit.pruneAuditLogs).toBe("function");
        expect("pruneAuditLogs" in kit.as(ACTOR)).toBe(false);
    });

    it("serialises the cutoff and lets SQL default the batch size", async () => {
        const { kit, calls } = kitWith([{ deleted_count: 7, lock_acquired: true }]);

        const result = await kit.pruneAuditLogs({
            before: new Date("2026-06-01T00:00:00.000Z"),
        });

        expect(calls[0]).toEqual([
            "prune_audit_logs",
            {
                p_before: "2026-06-01T00:00:00.000Z",
                p_tenant_id: null,
                p_limit: undefined,
            },
        ]);
        expect(result).toEqual({ deleted_count: 7, lock_acquired: true });
    });

    it("reports a lock it did not get as distinct from nothing to do", async () => {
        const { kit } = kitWith([{ deleted_count: 0, lock_acquired: false }]);

        // Both say zero rows. A loop that cannot tell them apart either spins or stops early.
        await expect(
            kit.pruneAuditLogs({ before: "2026-06-01T00:00:00.000Z" }),
        ).resolves.toEqual({ deleted_count: 0, lock_acquired: false });
    });

    it("fails loudly if the function returns nothing", async () => {
        const { kit } = kitWith([]);

        // Unlike logAudit, this one must not swallow: a retention job that silently does
        // nothing looks identical to one that is keeping up.
        await expect(
            kit.pruneAuditLogs({ before: "2026-06-01T00:00:00.000Z" }),
        ).rejects.toThrow(/returned no row/);
    });
});

describe("listAuditLogs", () => {
    it("passes every filter by its SQL parameter name", async () => {
        const transport = stubTransport();
        const from = new Date("2026-09-01T00:00:00.000Z");

        await createReadApi(transport, ACTOR).listAuditLogs({
            tenantId: TENANT,
            actorPrincipalId: PRINCIPAL,
            action: "grant_role",
            outcome: "denied",
            from,
            limit: 50,
        });

        expect(transport.calls[0]).toEqual([
            "list_audit_logs",
            {
                p_actor_principal_id: ACTOR,
                p_tenant_id: TENANT,
                p_actor_id: PRINCIPAL,
                p_action: "grant_role",
                p_target_type: null,
                p_target_id: null,
                p_request_id: null,
                p_outcome: "denied",
                p_from: "2026-09-01T00:00:00.000Z",
                p_to: null,
                p_limit: 50,
                p_after: undefined,
            },
        ]);
    });

    it("defaults to every row the actor may see", async () => {
        const transport = stubTransport();

        await createReadApi(transport, ACTOR).listAuditLogs();

        // Null tenant is "everything readable", not "rows with no tenant" -- the subtree case.
        expect(transport.calls[0]?.[1]).toMatchObject({
            p_tenant_id: null,
            p_limit: 100,
        });
    });
});
