/**
 * The access posture, asserted rather than assumed.
 *
 * Exposing `authz` to PostgREST leaves the grants as the only thing between the internet and
 * functions like `provision_admin`, which hands out master admin with no check at all. Every
 * one of these would otherwise fail silently: migra does not diff privileges, and Postgres
 * grants EXECUTE to PUBLIC on every new function no matter what default privileges say.
 */
import { createClient } from "@supabase/supabase-js";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
    AUTHZ_FUNCTIONS,
    AuthzConfigError,
    createAuthKit,
    fromSupabase,
} from "../../src/index.js";
import {
    DB_URL,
    PUBLISHABLE_KEY,
    SUPABASE_URL,
    apiAvailable,
    databaseAvailable,
    secretClient,
} from "./stack.js";

describe.skipIf(!databaseAvailable)("authz privileges", () => {
    let client: Client;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();
    });

    afterAll(async () => {
        await client?.end();
    });

    async function names(sql: string): Promise<string[]> {
        const { rows } = await client.query(sql);

        return rows.map(row => row.name as string).sort();
    }

    it("grants no authz function to PUBLIC", async () => {
        expect(
            await names(`
                select p.proname as name
                  from pg_proc p
                  join pg_namespace n on n.oid = p.pronamespace
                 cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                 where n.nspname = 'authz'
                   and a.grantee = 0
                   and a.privilege_type = 'EXECUTE'
            `),
        ).toEqual([]);
    });

    it("gives anon and authenticated nothing in authz", async () => {
        for (const role of ["anon", "authenticated"]) {
            const { rows } = await client.query(
                "select has_schema_privilege($1, 'authz', 'USAGE') as usage",
                [role],
            );

            expect(rows[0].usage).toBe(false);

            expect(
                await names(`
                    select p.proname as name
                      from pg_proc p
                      join pg_namespace n on n.oid = p.pronamespace
                     where n.nspname = 'authz'
                       and has_function_privilege('${role}', p.oid, 'EXECUTE')
                `),
            ).toEqual([]);
        }
    });

    // Adding a function to core without granting it -- or granting something core does not
    // call -- fails here instead of in production.
    it("lets service_role execute exactly the functions core calls", async () => {
        expect(
            await names(`
                select p.proname as name
                  from pg_proc p
                  join pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'authz'
                   and has_function_privilege('service_role', p.oid, 'EXECUTE')
            `),
        ).toEqual([...AUTHZ_FUNCTIONS].sort());

        const { rows } = await client.query(
            "select has_schema_privilege('service_role', 'authz', 'USAGE') as usage",
        );

        expect(rows[0].usage).toBe(true);
    });

    it("carries no default privilege that would expose a future function", async () => {
        const { rows } = await client.query(`
            select d.defaclacl::text as acl
              from pg_default_acl d
              join pg_namespace n on n.oid = d.defaclnamespace
             where n.nspname = 'authz'
        `);

        for (const row of rows) {
            expect(row.acl).not.toMatch(/service_role|anon|authenticated|(^|[{,])=/);
        }
    });

    // PostgREST cannot tell overloads apart when arguments arrive by name.
    it("overloads no function name", async () => {
        expect(
            await names(`
                select p.proname as name
                  from pg_proc p
                  join pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'authz'
                 group by p.proname
                having count(*) > 1
            `),
        ).toEqual([]);
    });

    // bindings_in_force is an invoker function so the planner can inline it. That is safe only
    // while nothing but the owner, from inside a security definer function, can reach it.
    it("keeps the inlinable bindings_in_force an owner-only invoker function", async () => {
        const { rows } = await client.query(`
            select p.prosecdef as definer, p.proconfig as config
              from pg_proc p
              join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = 'authz' and p.proname = 'bindings_in_force'
        `);

        expect(rows).toEqual([{ definer: false, config: null }]);
        expect(AUTHZ_FUNCTIONS).not.toContain("bindings_in_force");
    });
});

describe.skipIf(!apiAvailable)("authz over HTTP", () => {
    it("refuses the publishable key", async () => {
        const kit = createAuthKit({
            supabase: createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
                auth: { persistSession: false, autoRefreshToken: false },
            }),
            verifyBearer: async () => null,
        });

        const error = await kit
            .hasScope(
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "authz.roles.read",
            )
            .catch(e => e);

        expect(error).toBeInstanceOf(AuthzConfigError);
        expect(error.sqlState).toBe("42501");
    });

    it("refuses even the secret key the bootstrap functions that carry no check", async () => {
        const transport = fromSupabase(secretClient());

        for (const fn of ["provision_admin", "reclaim_identity"]) {
            await expect(
                // Deliberately outside AuthzFunction: core must never call these.
                transport.scalar(fn as never, { p_email: "nobody@example.com" }),
            ).rejects.toMatchObject({ code: "42501" });
        }
    });
});
