import { describe, expect, it, vi } from "vitest";

import {
    ForbiddenError,
    TenantRequiredError,
    UnauthenticatedError,
    checkAllScopes,
    checkAnyScope,
    checkScope,
    createAuthKit,
    createAuthzContext,
    credentialsFromHeaders,
    enforceGuard,
    type ResolvedPrincipal,
} from "../src/index.js";
import type { Row } from "../src/query.js";

const TENANT = "22222222-2222-4222-8222-222222222222";
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";

function contextWith(
    resolved: ResolvedPrincipal,
    scopes: string[] = [],
    options: { audit?: { denials?: boolean } } = {},
) {
    // Denial logging writes through the same query hook, so scope lookups are counted on their
    // own: "one round trip" has always meant one effective_scopes call, and an audit row is not
    // one of those.
    const audited: unknown[][] = [];
    const scopeQueries = vi.fn();

    const query = vi.fn(async (sql: string, params: readonly unknown[]): Promise<Row[]> => {
        if (sql.includes("effective_scopes")) {
            scopeQueries();

            return scopes.map(s => ({ scope_name: s }));
        }

        if (sql.includes("log_audit")) {
            audited.push([...params]);

            return [{ result: "audit-row" }];
        }

        throw new Error(`unexpected sql: ${sql}`);
    });

    const kit = createAuthKit({
        query,
        verifyBearer: async () => null,
        ...(options.audit === undefined ? {} : { audit: options.audit }),
    });

    return {
        context: createAuthzContext(kit, resolved, { requestId: "req-1", method: "GET" }),
        query: scopeQueries,
        audited,
    };
}

const anonymous: ResolvedPrincipal = {
    principalId: null,
    kind: null,
    credentialPresented: false,
};

const unresolved: ResolvedPrincipal = {
    principalId: null,
    kind: null,
    credentialPresented: true,
};

const user: ResolvedPrincipal = {
    principalId: PRINCIPAL,
    kind: "user",
    credentialPresented: true,
};

describe("enforceGuard", () => {
    it("rejects no credential as unauthenticated", async () => {
        const { context } = contextWith(anonymous);

        await expect(
            enforceGuard(context, () => TENANT, checkScope("x")),
        ).rejects.toBeInstanceOf(UnauthenticatedError);
    });

    // Open question 1: a credential that verified but maps to no authz identity.
    it("rejects a presented-but-unresolved credential as forbidden", async () => {
        const { context } = contextWith(unresolved);

        await expect(
            enforceGuard(context, () => TENANT, checkScope("x")),
        ).rejects.toBeInstanceOf(ForbiddenError);
    });

    it("never consults the tenant hook without a principal", async () => {
        const { context } = contextWith(anonymous);
        const resolveTenant = vi.fn(() => TENANT);

        await enforceGuard(context, resolveTenant, checkScope("x")).catch(() => {});

        expect(resolveTenant).not.toHaveBeenCalled();
    });

    it("rejects a non-uuid tenant without running the check", async () => {
        const { context, query } = contextWith(user);
        const check = vi.fn(async () => {});

        await expect(
            enforceGuard(context, () => "not-a-uuid", check),
        ).rejects.toBeInstanceOf(TenantRequiredError);
        expect(check).not.toHaveBeenCalled();
        expect(query).not.toHaveBeenCalled();
    });

    it("awaits an async tenant hook", async () => {
        const { context } = contextWith(user, ["x"]);

        await expect(
            enforceGuard(context, async () => TENANT, checkScope("x")),
        ).resolves.toBeUndefined();
    });

    it("rejects a missing scope as forbidden, naming it", async () => {
        const { context } = contextWith(user, ["y"]);

        const error = await enforceGuard(context, () => TENANT, checkScope("x")).catch(
            (e: unknown) => e,
        );

        expect(error).toBeInstanceOf(ForbiddenError);
        expect((error as ForbiddenError).scope).toBe("x");
    });
});

describe("denial logging", () => {
    it("records a denied row when a scope is missing", async () => {
        const { context, audited } = contextWith(user, ["y"]);

        await enforceGuard(context, () => TENANT, checkScope("x")).catch(() => {});

        expect(audited).toHaveLength(1);
        // The actor, the tenant it was asked about, and the refusal's own words.
        expect(audited[0]).toEqual(
            expect.arrayContaining([PRINCIPAL, TENANT, "authorize", "missing scope x"]),
        );
    });

    it("records a credential that maps to no identity, with no tenant", async () => {
        const { context, audited } = contextWith(unresolved);

        await enforceGuard(context, () => TENANT, checkScope("x")).catch(() => {});

        // The guard refuses before resolving a tenant, so there is none to anchor to: a
        // platform-level row, readable with authz.audit.read at the master.
        expect(audited).toHaveLength(1);
        expect(audited[0]).toEqual(expect.arrayContaining(["authenticate", "request"]));
        expect(audited[0]).not.toContain(TENANT);
    });

    it("records nothing for a request that presented no credential", async () => {
        const { context, audited } = contextWith(anonymous);

        await enforceGuard(context, () => TENANT, checkScope("x")).catch(() => {});

        // Nobody was refused anything -- the request did not say who it was. Logging 401s
        // would turn every unauthenticated probe into a write.
        expect(audited).toHaveLength(0);
    });

    it("records nothing for an unresolvable tenant", async () => {
        const { context, audited } = contextWith(user, ["x"]);

        await enforceGuard(context, () => "not-a-uuid", checkScope("x")).catch(() => {});

        // A malformed request, not a refusal.
        expect(audited).toHaveLength(0);
    });

    it("is off when audit.denials is false", async () => {
        const { context, audited } = contextWith(user, ["y"], {
            audit: { denials: false },
        });

        await enforceGuard(context, () => TENANT, checkScope("x")).catch(() => {});

        expect(audited).toHaveLength(0);
    });

    it("still denies when the audit row cannot be written", async () => {
        const query = vi.fn(async (sql: string): Promise<Row[]> => {
            if (sql.includes("effective_scopes")) return [];

            throw new Error("audit insert failed");
        });

        const kit = createAuthKit({ query, verifyBearer: async () => null });
        const context = createAuthzContext(kit, user);

        // The guard's answer must not depend on whether the log accepted the row.
        await expect(
            enforceGuard(context, () => TENANT, checkScope("x")),
        ).rejects.toBeInstanceOf(ForbiddenError);
    });
});

describe("scope checks", () => {
    it("checkAllScopes needs every scope and costs one round trip", async () => {
        const { context, query } = contextWith(user, ["a", "b"]);

        await expect(
            enforceGuard(context, () => TENANT, checkAllScopes(["a", "b"])),
        ).resolves.toBeUndefined();
        await expect(
            enforceGuard(context, () => TENANT, checkAllScopes(["a", "c"])),
        ).rejects.toBeInstanceOf(ForbiddenError);
        expect(query).toHaveBeenCalledOnce();
    });

    it("checkAnyScope needs at least one scope", async () => {
        const { context } = contextWith(user, ["b"]);

        await expect(
            enforceGuard(context, () => TENANT, checkAnyScope(["a", "b"])),
        ).resolves.toBeUndefined();
        await expect(
            enforceGuard(context, () => TENANT, checkAnyScope(["a", "c"])),
        ).rejects.toBeInstanceOf(ForbiddenError);
    });

    // The promise is memoized, not the value, so concurrent checks coalesce.
    it("coalesces concurrent scope lookups into one query", async () => {
        const { context, query } = contextWith(user, ["a"]);

        await Promise.all([context.has(TENANT, "a"), context.has(TENANT, "b")]);

        expect(query).toHaveBeenCalledOnce();
    });
});

describe("credentialsFromHeaders", () => {
    it("reads a bearer token and an API key", () => {
        expect(
            credentialsFromHeaders({
                authorization: "Bearer tok",
                "x-api-key": "sak_x_y",
            }),
        ).toEqual({ apiKey: "sak_x_y", bearer: "tok" });
    });

    it("ignores a non-Bearer scheme", () => {
        expect(credentialsFromHeaders({ authorization: "Basic dXNlcg==" }).bearer).toBeNull();
    });

    it("treats an array-valued API-key header as no key", () => {
        expect(credentialsFromHeaders({ "x-api-key": ["a", "b"] }).apiKey).toBeNull();
    });

    it("honours a custom API-key header, case-insensitively", () => {
        expect(
            credentialsFromHeaders({ "x-service-key": "sak_x_y" }, "X-Service-Key").apiKey,
        ).toBe("sak_x_y");
    });
});
