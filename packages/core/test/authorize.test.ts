import { describe, expect, it, vi } from "vitest";

import { effectiveScopes, hasScope } from "../src/authorize.js";
import type { QueryFn, Row } from "../src/query.js";
import { fromQuery } from "../src/transport.js";

/** Records every call so a test can assert the database was *not* consulted. */
function stubQuery(rows: Row[] = []): QueryFn & { calls: unknown[][] } {
    const calls: unknown[][] = [];

    const query = vi.fn(async (sql: string, params: readonly unknown[]) => {
        calls.push([sql, params]);

        return rows;
    }) as unknown as QueryFn & { calls: unknown[][] };

    query.calls = calls;

    return query;
}

const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";

describe("hasScope fails closed", () => {
    it("denies a null principal without querying", async () => {
        const query = stubQuery([{ result: true }]);

        expect(await hasScope(fromQuery(query), null, TENANT, "authz.roles.read")).toBe(
            false,
        );
        expect(query.calls).toHaveLength(0);
    });

    it("denies a null tenant without querying", async () => {
        const query = stubQuery([{ result: true }]);

        expect(await hasScope(fromQuery(query), PRINCIPAL, null, "authz.roles.read")).toBe(
            false,
        );
        expect(query.calls).toHaveLength(0);
    });

    // The failure this guards against is the opposite of the one above: a short circuit that
    // *skips* the check and lets the request through. A null must never reach a truthy branch.
    it("does consult the database when both are present", async () => {
        const query = stubQuery([{ result: true }]);

        expect(await hasScope(fromQuery(query), PRINCIPAL, TENANT, "authz.roles.read")).toBe(
            true,
        );
        expect(query.calls).toHaveLength(1);
        expect(query.calls[0]?.[1]).toEqual([
            PRINCIPAL,
            TENANT,
            "authz.roles.read",
        ]);
    });

    it("denies when SQL says false", async () => {
        const query = stubQuery([{ result: false }]);

        expect(await hasScope(fromQuery(query), PRINCIPAL, TENANT, "app.thing")).toBe(false);
    });

    // A driver returning something other than a native boolean must not read as permission.
    it("denies on an unexpected result shape rather than coercing", async () => {
        for (const rows of [[], [{}], [{ result: "t" }], [{ result: 1 }]]) {
            expect(await hasScope(fromQuery(stubQuery(rows)), PRINCIPAL, TENANT, "x")).toBe(
                false,
            );
        }
    });
});

describe("effectiveScopes", () => {
    it("is empty for a null principal or tenant, without querying", async () => {
        const query = stubQuery([{ scope_name: "app.thing" }]);

        expect(await effectiveScopes(fromQuery(query), null, TENANT)).toEqual([]);
        expect(await effectiveScopes(fromQuery(query), PRINCIPAL, null)).toEqual([]);
        expect(query.calls).toHaveLength(0);
    });

    it("returns scope names verbatim, with no case mapping", async () => {
        const query = stubQuery([
            { scope_name: "authz.roles.write" },
            { scope_name: "authz.bindings.grant" },
        ]);

        expect(await effectiveScopes(fromQuery(query), PRINCIPAL, TENANT)).toEqual([
            "authz.roles.write",
            "authz.bindings.grant",
        ]);
    });
});
