/**
 * Runs against a real local Supabase stack (`npx supabase start` in apps/installer).
 *
 * Skipped when the database is unreachable, so `npm run test` stays green without Docker. The
 * point of these is the seam the unit tests cannot reach: that the TypeScript short circuits
 * agree with what SQL actually answers.
 */
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createAuthKit, type QueryFn } from "../../src/index.js";

const DB_URL =
    process.env["AUTHZ_TEST_DATABASE_URL"] ??
    "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

const TENANT_ADMIN_ROLE = "a0000000-0000-4000-8000-000000000003";

async function reachable(): Promise<boolean> {
    const probe = new Client({ connectionString: DB_URL });

    try {
        await probe.connect();
        await probe.end();

        return true;
    } catch {
        return false;
    }
}

const available = await reachable();

describe.skipIf(!available)("core against a live authz schema", () => {
    let client: Client;
    let query: QueryFn;
    let kit: ReturnType<typeof createAuthKit>;

    const suffix = Math.random().toString(36).slice(2, 10);
    const operatorEmail = `itest-op-${suffix}@example.com`;
    const memberEmail = `itest-member-${suffix}@example.com`;

    let tenantId: string;
    let memberPrincipal: string;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();

        query = (sql, params) =>
            client.query(sql, params as unknown[]).then(r => r.rows);

        // verifyBearer is never exercised here; the identity paths under test are the SQL ones.
        kit = createAuthKit({ query, verifyBearer: async () => null });

        const operator = await one<string>(
            "select authz.provision_admin($1) as result",
            [operatorEmail],
        );
        const operatorPrincipal = await one<string>(
            "select p.id as result from authz.principals p join authz.users u on u.id = p.user_id where u.id = $1",
            [operator],
        );

        tenantId = await one<string>(
            "select authz.create_tenant($1, authz.master_tenant_id(), $2) as result",
            [operatorPrincipal, `itest-${suffix}`],
        );

        await one<string>(
            "select authz.invite_user($1, $2, $3, $4) as result",
            [operatorPrincipal, tenantId, memberEmail, TENANT_ADMIN_ROLE],
        );

        memberPrincipal = await one<string>(
            "select p.id as result from authz.principals p join authz.users u on u.id = p.user_id where u.email_id = authz.email_id($1)",
            [memberEmail],
        );
    });

    afterAll(async () => {
        await client?.end();
    });

    async function one<T>(sql: string, params: unknown[]): Promise<T> {
        const { rows } = await client.query(sql, params);

        return rows[0].result as T;
    }

    /**
     * The property the unit tests assert on the TypeScript side only. If SQL ever started
     * answering true for a null principal, the short circuit in `hasScope` would be hiding it.
     */
    it("agrees with SQL that a null principal holds nothing", async () => {
        expect(
            await one<boolean | null>(
                "select authz.has_scope(null, $1, $2) as result",
                [tenantId, "authz.roles.read"],
            ),
        ).not.toBe(true);

        expect(await kit.hasScope(null, tenantId, "authz.roles.read")).toBe(false);
    });

    it("agrees with SQL that a null tenant holds nothing", async () => {
        expect(
            await one<boolean | null>(
                "select authz.has_scope($1, null, $2) as result",
                [memberPrincipal, "authz.roles.read"],
            ),
        ).not.toBe(true);

        expect(await kit.hasScope(memberPrincipal, null, "authz.roles.read")).toBe(
            false,
        );
    });

    it("grants a tenant_admin the scopes that role actually carries", async () => {
        expect(
            await kit.hasScope(memberPrincipal, tenantId, "authz.roles.write"),
        ).toBe(true);

        // tenant_admin is deliberately the 13 scopes excluding the global person lifecycle.
        expect(
            await kit.hasScope(memberPrincipal, tenantId, "authz.users.write"),
        ).toBe(false);

        const scopes = await kit.effectiveScopes(memberPrincipal, tenantId);

        expect(scopes).toHaveLength(13);
        expect(scopes).not.toContain("authz.users.write");
        expect(scopes).toContain("authz.bindings.grant");
    });

    it("does not leak a tenant's scopes to its parent", async () => {
        const master = await one<string>(
            "select authz.master_tenant_id() as result",
            [],
        );

        expect(await kit.hasScope(memberPrincipal, master, "authz.roles.write")).toBe(
            false,
        );
    });

    it("resolves a provisioned identity to no principal until it is claimed", async () => {
        // invite_user provisions an unclaimed identity: no auth.users row exists for it yet, so
        // nothing can match auth_user_id.
        const authUserId = await one<string | null>(
            "select u.auth_user_id as result from authz.users u where u.email_id = authz.email_id($1)",
            [memberEmail],
        );

        expect(authUserId).toBeNull();
        expect(
            await one<string | null>(
                "select authz.principal_for_auth_user(null) as result",
                [],
            ),
        ).toBeNull();
    });

    it("reports an unclaimed principal as inactive", async () => {
        expect(await kit.principalIsActive(memberPrincipal)).toBe(false);
    });
});
