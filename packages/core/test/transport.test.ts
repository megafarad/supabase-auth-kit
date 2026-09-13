import { describe, expect, it, vi } from "vitest";

import {
    AuthzConfigError,
    AuthzDeniedError,
    AuthzUsageError,
    createAuthKit,
} from "../src/index.js";
import type { QueryFn, Row } from "../src/query.js";
import {
    fromQuery,
    fromSupabase,
    type AuthzFunction,
    type SupabaseRpcError,
} from "../src/transport.js";

const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";

function recordingQuery(rows: Row[] = []): QueryFn & {
    calls: { sql: string; params: readonly unknown[] }[];
} {
    const calls: { sql: string; params: readonly unknown[] }[] = [];

    const query = (async (sql: string, params: readonly unknown[]) => {
        calls.push({ sql, params });

        return rows;
    }) as QueryFn & { calls: typeof calls };

    query.calls = calls;

    return query;
}

/** A supabase-js stand-in that records the schema and RPC it was asked for. */
function fakeSupabase(response: { data: unknown; error: SupabaseRpcError | null }) {
    const rpc = vi.fn(async (_fn: string, _args?: Record<string, unknown>) => response);
    const schema = vi.fn((_schema: string) => ({ rpc }));

    return { client: { schema }, schema, rpc };
}

describe("fromQuery", () => {
    it("calls a scalar function with named arguments, bound as parameters", async () => {
        const query = recordingQuery([{ result: true }]);

        const value = await fromQuery(query).scalar("has_scope", {
            p_principal_id: PRINCIPAL,
            p_tenant_id: TENANT,
            p_scope: "authz.roles.read",
        });

        expect(value).toBe(true);
        expect(query.calls).toEqual([
            {
                sql: "select authz.has_scope(p_principal_id => $1, p_tenant_id => $2, p_scope => $3) as result",
                params: [PRINCIPAL, TENANT, "authz.roles.read"],
            },
        ]);
    });

    it("selects every column from a set-returning function", async () => {
        const query = recordingQuery([{ scope_name: "a" }]);

        expect(
            await fromQuery(query).rows("effective_scopes", {
                p_principal_id: PRINCIPAL,
                p_tenant_id: TENANT,
            }),
        ).toEqual([{ scope_name: "a" }]);
        expect(query.calls[0]?.sql).toBe(
            "select * from authz.effective_scopes(p_principal_id => $1, p_tenant_id => $2)",
        );
    });

    // undefined lets the SQL default apply; null must still reach SQL as a null.
    it("omits undefined arguments and keeps nulls", async () => {
        const query = recordingQuery([]);

        await fromQuery(query).rows("list_roles", {
            p_actor_principal_id: PRINCIPAL,
            p_tenant_id: null,
            p_after: undefined,
        });

        expect(query.calls[0]).toEqual({
            sql: "select * from authz.list_roles(p_actor_principal_id => $1, p_tenant_id => $2)",
            params: [PRINCIPAL, null],
        });
    });

    it("reads a missing or null scalar as null", async () => {
        expect(await fromQuery(recordingQuery([])).scalar("verify_api_key", { p_key: "k" })).toBeNull();
        expect(
            await fromQuery(recordingQuery([{ result: null }])).scalar("verify_api_key", {
                p_key: "k",
            }),
        ).toBeNull();
    });

    // pg hands back Date objects; PostgREST can only send strings. Both must look the same.
    it("normalises timestamps to ISO strings", async () => {
        const at = new Date("2026-09-12T10:00:00.000Z");
        const query = recordingQuery([{ granted_at: at, expires_at: null }]);

        expect(await fromQuery(query).rows("list_principal_bindings", {})).toEqual([
            { granted_at: "2026-09-12T10:00:00.000Z", expires_at: null },
        ]);
    });

    // Names are the one thing interpolated into SQL text. Types are erased at runtime.
    it("refuses a function or argument name that is not a plain identifier", async () => {
        const query = recordingQuery([]);
        const transport = fromQuery(query);

        await expect(
            transport.scalar("has_scope(); drop table x; --" as AuthzFunction, {}),
        ).rejects.toThrow(TypeError);
        await expect(
            transport.scalar("has_scope", { "p_scope => $1); --": "x" }),
        ).rejects.toThrow(TypeError);
        expect(query.calls).toHaveLength(0);
    });
});

describe("fromSupabase", () => {
    it("calls the RPC on the authz schema with the arguments by name", async () => {
        const fake = fakeSupabase({ data: true, error: null });

        expect(
            await fromSupabase(fake.client).scalar("has_scope", {
                p_principal_id: PRINCIPAL,
                p_tenant_id: TENANT,
                p_scope: "x",
                p_unused: undefined,
            }),
        ).toBe(true);
        expect(fake.schema).toHaveBeenCalledWith("authz");
        expect(fake.rpc).toHaveBeenCalledWith("has_scope", {
            p_principal_id: PRINCIPAL,
            p_tenant_id: TENANT,
            p_scope: "x",
        });
    });

    it("reads a void function's null data as null", async () => {
        const fake = fakeSupabase({ data: null, error: null });

        expect(
            await fromSupabase(fake.client).scalar("revoke_binding", {
                p_actor_principal_id: PRINCIPAL,
                p_binding_id: TENANT,
            }),
        ).toBeNull();
    });

    it("throws PostgREST's error with its code, rather than resolving", async () => {
        const fake = fakeSupabase({
            data: null,
            error: { code: "P0001", message: "principal lacks authz.tenants.write", details: null, hint: null },
        });

        await expect(fromSupabase(fake.client).scalar("create_tenant", {})).rejects.toMatchObject({
            code: "P0001",
            message: "principal lacks authz.tenants.write",
        });
    });

    it("refuses a set that is not an array instead of pretending it is empty", async () => {
        const fake = fakeSupabase({ data: "nope", error: null });

        await expect(fromSupabase(fake.client).rows("list_roles", {})).rejects.toThrow(TypeError);
    });
});

describe("createAuthKit transport selection", () => {
    const verifyBearer = async () => null;

    it("requires exactly one of supabase, query or transport", () => {
        const query = recordingQuery([]);
        const { client } = fakeSupabase({ data: null, error: null });

        expect(() => createAuthKit({ verifyBearer })).toThrow(/exactly one/);
        expect(() => createAuthKit({ query, supabase: client, verifyBearer })).toThrow(
            /exactly one/,
        );
        expect(() =>
            createAuthKit({ query, transport: fromQuery(query), verifyBearer }),
        ).toThrow(/exactly one/);
    });

    it("types errors the same way whichever transport raised them", async () => {
        const denied = fakeSupabase({
            data: null,
            error: { code: "P0001", message: "no" },
        });
        const kit = createAuthKit({ supabase: denied.client, verifyBearer });

        await expect(kit.as(PRINCIPAL).createTenant(TENANT, "x")).rejects.toThrow(
            AuthzDeniedError,
        );

        const pgDenied: QueryFn = async () => {
            throw Object.assign(new Error("no"), { code: "P0001" });
        };

        await expect(
            createAuthKit({ query: pgDenied, verifyBearer }).as(PRINCIPAL).createTenant(TENANT, "x"),
        ).rejects.toThrow(AuthzDeniedError);
    });

    // Wiring failures must not read as 403s, and should say how to fix them.
    it("maps an unexposed schema, an unknown function and a permission error to AuthzConfigError", async () => {
        for (const code of ["PGRST106", "PGRST202", "42501"]) {
            const fake = fakeSupabase({ data: null, error: { code, message: "boom" } });
            const kit = createAuthKit({ supabase: fake.client, verifyBearer });

            const error = await kit.hasScope(PRINCIPAL, TENANT, "x").catch(e => e);

            expect(error).toBeInstanceOf(AuthzConfigError);
            expect(error.sqlState).toBe(code);
            expect(error.message).toMatch(/^boom: /);
        }
    });

    it("maps a value that does not cast to AuthzUsageError", async () => {
        const fake = fakeSupabase({
            data: null,
            error: { code: "22P02", message: "invalid input syntax for type uuid" },
        });
        const kit = createAuthKit({ supabase: fake.client, verifyBearer });

        await expect(kit.as(PRINCIPAL).revokeBinding("not-a-uuid")).rejects.toThrow(
            AuthzUsageError,
        );
    });

    it("passes an unrecognised failure through untouched", async () => {
        const reset = Object.assign(new Error("fetch failed"), { code: "" });
        const kit = createAuthKit({
            transport: {
                scalar: async () => {
                    throw reset;
                },
                rows: async () => [],
            },
            verifyBearer,
        });

        await expect(kit.hasScope(PRINCIPAL, TENANT, "x")).rejects.toBe(reset);
    });
});
