/**
 * The write API against a real local Supabase stack. Skipped when the database is unreachable.
 *
 * These exist to prove two things the unit tests cannot: that the pre-bound actor reaches the
 * SQL functions in the right position, and that a guard's refusal surfaces as a typed
 * AuthzDeniedError rather than an opaque driver error.
 */
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AuthzDeniedError, createAuthKit, type QueryFn } from "../../src/index.js";

const DB_URL =
    process.env["AUTHZ_TEST_DATABASE_URL"] ??
    "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

const ADMIN_ROLE = "a0000000-0000-4000-8000-000000000002";
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

describe.skipIf(!available)("write API against a live authz schema", () => {
    let client: Client;
    let kit: ReturnType<typeof createAuthKit>;

    const suffix = Math.random().toString(36).slice(2, 10);
    const operatorEmail = `wtest-op-${suffix}@example.com`;
    const memberEmail = `wtest-member-${suffix}@example.com`;

    let operatorPrincipal: string;
    let memberPrincipal: string;
    let tenantId: string;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();

        const query: QueryFn = (sql, params) =>
            client.query(sql, params as unknown[]).then(r => r.rows);

        kit = createAuthKit({ query, verifyBearer: async () => null });

        const operatorUser = await one<string>(
            "select authz.provision_admin($1) as result",
            [operatorEmail],
        );
        operatorPrincipal = await one<string>(
            "select p.id as result from authz.principals p where p.user_id = $1",
            [operatorUser],
        );

        tenantId = await kit.as(operatorPrincipal).createTenant(
            await one<string>("select authz.master_tenant_id() as result", []),
            `wtest-${suffix}`,
        );

        await kit.as(operatorPrincipal).inviteUser(
            tenantId,
            memberEmail,
            TENANT_ADMIN_ROLE,
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

    it("round-trips a role, a scope and their link", async () => {
        const as = kit.as(memberPrincipal);

        const roleId = await as.createRole(tenantId, `editor-${suffix}`, "Editor");
        const scopeId = await as.createScope(tenantId, `app.edit.${suffix}`, null);

        await as.addRoleScope(roleId, scopeId);

        expect(
            await one<number>(
                "select count(*)::int as result from authz.role_scopes where role_id = $1",
                [roleId],
            ),
        ).toBe(1);

        await as.removeRoleScope(roleId, scopeId);

        expect(
            await one<number>(
                "select count(*)::int as result from authz.role_scopes where role_id = $1",
                [roleId],
            ),
        ).toBe(0);
    });

    it("grants and revokes a binding, and the scope follows", async () => {
        const as = kit.as(operatorPrincipal);

        const roleId = await as.createRole(tenantId, `viewer-${suffix}`, "Viewer");
        const scopeId = await as.createScope(tenantId, `app.view.${suffix}`, null);
        await as.addRoleScope(roleId, scopeId);

        const bindingId = await as.grantRole(memberPrincipal, roleId, tenantId);

        expect(
            await kit.hasScope(memberPrincipal, tenantId, `app.view.${suffix}`),
        ).toBe(true);

        await as.revokeBinding(bindingId);

        expect(
            await kit.hasScope(memberPrincipal, tenantId, `app.view.${suffix}`),
        ).toBe(false);
    });

    // The rule the whole scope split rests on, reached through TypeScript.
    it("maps the cannot-grant-what-you-do-not-hold guard to AuthzDeniedError", async () => {
        await expect(
            kit.as(memberPrincipal).grantRole(memberPrincipal, ADMIN_ROLE, tenantId),
        ).rejects.toThrow(AuthzDeniedError);

        await expect(
            kit.as(memberPrincipal).grantRole(memberPrincipal, ADMIN_ROLE, tenantId),
        ).rejects.toThrow(/does not hold authz\.users\.write/);
    });

    it("maps the master-gated crosses_boundary guard to AuthzDeniedError", async () => {
        await expect(
            kit
                .as(memberPrincipal)
                .createRole(tenantId, `escape-${suffix}`, "Escapes", true),
        ).rejects.toThrow(AuthzDeniedError);
    });

    it("lets the operator create a crossing role in the same place", async () => {
        await expect(
            kit
                .as(operatorPrincipal)
                .createRole(tenantId, `support-${suffix}`, "Support", true),
        ).resolves.toBeTypeOf("string");
    });

    it("issues an API key that resolves, then stops resolving once revoked", async () => {
        const as = kit.as(memberPrincipal);

        const key = await as.createApiKey(tenantId, `ci-${suffix}`, null);

        expect(key.startsWith("sak_")).toBe(true);
        expect(await kit.principalForApiKey(key)).not.toBeNull();

        const apiKeyId = await one<string>(
            "select id as result from authz.api_keys where label = $1",
            [`ci-${suffix}`],
        );

        await as.revokeApiKey(apiKeyId);

        expect(await kit.principalForApiKey(key)).toBeNull();
    });

    it("refuses to invite into the reserved authz. scope namespace", async () => {
        await expect(
            kit
                .as(memberPrincipal)
                .createScope(tenantId, "authz.forged.write", "nope"),
        ).rejects.toThrow(AuthzDeniedError);
    });
});
