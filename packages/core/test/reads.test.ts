import { describe, expect, it, vi } from "vitest";

import { AuthzUsageError } from "../src/errors.js";
import { createReadApi } from "../src/reads.js";
import type { Row } from "../src/query.js";
import type { AuthzTransport, RpcArgs } from "../src/transport.js";

const ACTOR = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const CURSOR = "33333333-3333-4333-8333-333333333333role-name";

function transportReturning(rows: Row[]): AuthzTransport & {
    rowsCalls: [string, RpcArgs][];
} {
    const rowsCalls: [string, RpcArgs][] = [];

    return {
        rowsCalls,
        scalar: vi.fn(async () => null),
        rows: async (fn, args) => {
            rowsCalls.push([fn, args]);

            return rows;
        },
    };
}

function roles(count: number): Row[] {
    return Array.from({ length: count }, (_, i) => ({
        role_id: `r${i}`,
        name: `role-${i}`,
        page_cursor: `cursor-${i}`,
    }));
}

describe("read API paging", () => {
    it("binds the actor and passes the page through", async () => {
        const transport = transportReturning([]);

        await createReadApi(transport, ACTOR).listRoles(TENANT, {
            limit: 25,
            after: CURSOR,
        });

        expect(transport.rowsCalls).toEqual([
            [
                "list_roles",
                {
                    p_actor_principal_id: ACTOR,
                    p_tenant_id: TENANT,
                    p_limit: 25,
                    p_after: CURSOR,
                },
            ],
        ]);
    });

    it("strips page_cursor from rows and offers the last one as nextCursor on a full page", async () => {
        const page = await createReadApi(transportReturning(roles(2)), ACTOR).listRoles(TENANT, {
            limit: 2,
        });

        expect(page.rows).toEqual([
            { role_id: "r0", name: "role-0" },
            { role_id: "r1", name: "role-1" },
        ]);
        expect(page.nextCursor).toBe("cursor-1");
    });

    it("has no next cursor when the page came back short", async () => {
        const page = await createReadApi(transportReturning(roles(1)), ACTOR).listRoles(TENANT, {
            limit: 2,
        });

        expect(page.nextCursor).toBeNull();
    });

    // SQL clamps the limit too. Doing the same here is what lets a full page be recognised.
    it("clamps the limit to [1, 1000] and defaults it to 100", async () => {
        const transport = transportReturning([]);
        const api = createReadApi(transport, ACTOR);

        await api.listRoles(TENANT);
        await api.listRoles(TENANT, { limit: 0 });
        await api.listRoles(TENANT, { limit: 5000 });
        await api.listRoles(TENANT, { limit: 2.7 });
        await api.listRoles(TENANT, { limit: Number.NaN });

        expect(transport.rowsCalls.map(([, args]) => args["p_limit"])).toEqual([
            100, 1, 1000, 2, 100,
        ]);
    });

    it("lists the actor's own bindings through list_principal_bindings", async () => {
        const transport = transportReturning([]);

        await createReadApi(transport, ACTOR).listMyBindings();

        expect(transport.rowsCalls[0]?.[0]).toBe("list_principal_bindings");
        expect(transport.rowsCalls[0]?.[1]["p_principal_id"]).toBe(ACTOR);
    });

    it("excludes inherited bindings unless asked", async () => {
        const transport = transportReturning([]);
        const api = createReadApi(transport, ACTOR);

        await api.listTenantBindings(TENANT);
        await api.listTenantBindings(TENANT, { includeInherited: true });

        expect(transport.rowsCalls.map(([, args]) => args["p_include_inherited"])).toEqual([
            false,
            true,
        ]);
    });

    it("refuses a malformed cursor before reaching the database", async () => {
        const transport = transportReturning([]);

        await expect(
            createReadApi(transport, ACTOR).listRoles(TENANT, { after: "not-a-cursor" }),
        ).rejects.toThrow(AuthzUsageError);
        expect(transport.rowsCalls).toHaveLength(0);
    });

    it("answers getTenant with null when no row comes back", async () => {
        expect(await createReadApi(transportReturning([]), ACTOR).getTenant(TENANT)).toBeNull();
    });
});
