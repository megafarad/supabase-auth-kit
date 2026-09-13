/**
 * The read API against a real local Supabase stack, once per transport, plus a check that the
 * reads and the dormant RLS policies agree about who may see what.
 *
 * The fixture tree:
 *
 *   master
 *   └── A                  member: tenant_admin (unclaimed invite)
 *       │                  viewer: a custom role carrying one app scope and no authz.* read
 *       ├── c-1, c-2, c-3
 *       └── c-cut          inherit = false, so member's non-crossing binding does not reach it
 *
 * The operator holds the seeded `admin` at the master, which crosses boundaries.
 */
import { randomUUID } from "node:crypto";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
    AuthzUsageError,
    createAuthKit,
    type AuthKit,
    type Page,
} from "../../src/index.js";
import {
    DB_URL,
    TENANT_ADMIN_ROLE,
    TRANSPORTS,
    databaseAvailable,
    one,
    suffix as randomSuffix,
} from "./stack.js";

interface Fixture {
    suffix: string;
    master: string;
    tenantA: string;
    tenantAName: string;
    children: Record<"c-1" | "c-2" | "c-3" | "c-cut", string>;
    operator: string;
    member: string;
    memberEmail: string;
    viewer: string;
    viewerEmail: string;
    viewerRole: string;
    viewerRoleName: string;
    appScope: string;
    revokedBinding: string;
}

async function principalFor(client: Client, email: string): Promise<string> {
    return one<string>(
        client,
        "select p.id as result from authz.principals p join authz.users u on u.id = p.user_id where u.email_id = authz.email_id($1)",
        [email],
    );
}

/** Built over a direct owner connection and the pg transport, so it is identical for every suite. */
async function buildFixture(client: Client): Promise<Fixture> {
    const suffix = randomSuffix();
    const kit = createAuthKit({
        query: (sql, params) => client.query(sql, params as unknown[]).then(r => r.rows),
        verifyBearer: async () => null,
    });

    const operatorEmail = `rtest-op-${suffix}@example.com`;
    const memberEmail = `rtest-member-${suffix}@example.com`;
    const viewerEmail = `rtest-viewer-${suffix}@example.com`;
    const goneEmail = `rtest-gone-${suffix}@example.com`;

    await one(client, "select authz.provision_admin($1) as result", [operatorEmail]);
    const operator = await principalFor(client, operatorEmail);
    const master = await one<string>(client, "select authz.master_tenant_id() as result");

    const op = kit.as(operator);
    const tenantAName = `rtest-a-${suffix}`;
    const tenantA = await op.createTenant(master, tenantAName);

    await op.inviteUser(tenantA, memberEmail, TENANT_ADMIN_ROLE);
    const member = await principalFor(client, memberEmail);

    const viewerRoleName = `viewer-${suffix}`;
    const viewerRole = await op.createRole(tenantA, viewerRoleName, "Viewer");
    const appScope = await op.createScope(tenantA, `app.view.${suffix}`, "View things");
    await op.addRoleScope(viewerRole, appScope);
    await op.inviteUser(tenantA, viewerEmail, viewerRole);
    const viewer = await principalFor(client, viewerEmail);

    await op.inviteUser(tenantA, goneEmail, viewerRole);
    const revokedBinding = await one<string>(
        client,
        "select rb.id as result from authz.role_bindings rb where rb.principal_id = $1",
        [await principalFor(client, goneEmail)],
    );
    await op.revokeBinding(revokedBinding);

    const children = {
        "c-1": await op.createTenant(tenantA, `c-1`),
        "c-2": await op.createTenant(tenantA, `c-2`),
        "c-3": await op.createTenant(tenantA, `c-3`),
        "c-cut": await op.createTenant(tenantA, `c-cut`),
    };
    await op.updateTenant(children["c-cut"], { inherit: false });

    await op.createApiKey(tenantA, `ci-${suffix}`);

    return {
        suffix,
        master,
        tenantA,
        tenantAName,
        children,
        operator,
        member,
        memberEmail,
        viewer,
        viewerEmail,
        viewerRole,
        viewerRoleName,
        appScope,
        revokedBinding,
    };
}

/** Walks every page, so a test can assert paging neither loses nor repeats rows. */
async function allPages<T>(
    fetch: (after: string | null) => Promise<Page<T>>,
): Promise<{ rows: T[]; pages: number }> {
    const rows: T[] = [];
    let after: string | null = null;
    let pages = 0;

    do {
        const page = await fetch(after);

        rows.push(...page.rows);
        after = page.nextCursor;
        pages += 1;
    } while (after !== null && pages < 50);

    return { rows, pages };
}

describe.each(TRANSPORTS)("read API against a live authz schema ($name)", transport => {
    if (!transport.available) {
        it.skip("needs a reachable local stack", () => {});

        return;
    }

    let client: Client;
    let kit: AuthKit;
    let f: Fixture;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();

        f = await buildFixture(client);
        kit = createAuthKit({
            transport: transport.make(client),
            verifyBearer: async () => null,
        });
    });

    afterAll(async () => {
        await client?.end();
    });

    it("gets a tenant for someone who may read it, and nothing for anyone else", async () => {
        expect(await kit.as(f.member).getTenant(f.tenantA)).toMatchObject({
            tenant_id: f.tenantA,
            parent_id: f.master,
            name: f.tenantAName,
            inherit: true,
        });
        expect(await kit.as(f.viewer).getTenant(f.tenantA)).toBeNull();
    });

    it("returns timestamps as ISO strings", async () => {
        const tenant = await kit.as(f.member).getTenant(f.tenantA);

        expect(typeof tenant?.created_at).toBe("string");
        expect(Number.isNaN(Date.parse(tenant?.created_at ?? ""))).toBe(false);
    });

    it("pages child tenants by name without losing or repeating a row", async () => {
        const { rows, pages } = await allPages(after =>
            kit.as(f.operator).listChildTenants(f.tenantA, { limit: 2, after }),
        );

        expect(rows.map(r => r.name)).toEqual(["c-1", "c-2", "c-3", "c-cut"]);
        expect(pages).toBe(3);
    });

    // The inheriting-child shortcut in list_child_tenants must never admit a row has_scope
    // would refuse -- and c-cut is the child it must not wave through.
    it("hides a cut-off child from a non-crossing parent admin, and agrees with has_scope", async () => {
        const listed = (await kit.as(f.member).listChildTenants(f.tenantA)).rows.map(
            r => r.tenant_id,
        );

        expect(listed).not.toContain(f.children["c-cut"]);

        for (const child of Object.values(f.children)) {
            expect(listed.includes(child)).toBe(
                await kit.hasScope(f.member, child, "authz.tenants.read"),
            );
        }
    });

    it("shows a principal their own bindings with names, even without read scopes", async () => {
        const { rows } = await kit.as(f.viewer).listMyBindings();

        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
            principal_id: f.viewer,
            tenant_id: f.tenantA,
            tenant_name: f.tenantAName,
            role_id: f.viewerRole,
            role_name: f.viewerRoleName,
        });
    });

    it("lists another principal's bindings only with authz.bindings.read", async () => {
        expect((await kit.as(f.member).listPrincipalBindings(f.viewer)).rows).toHaveLength(1);
        expect((await kit.as(f.viewer).listPrincipalBindings(f.member)).rows).toEqual([]);
    });

    it("lists a tenant's members, pending invites included and revoked bindings excluded", async () => {
        const { rows } = await kit.as(f.member).listTenantBindings(f.tenantA);
        const byPrincipal = new Map(rows.map(r => [r.principal_id, r]));

        expect(byPrincipal.get(f.member)).toMatchObject({
            principal_kind: "user",
            email: f.memberEmail,
            claimed: false,
            role_id: TENANT_ADMIN_ROLE,
            role_name: "tenant_admin",
            source_tenant_id: f.tenantA,
            inherited: false,
        });
        expect(byPrincipal.get(f.viewer)?.email).toBe(f.viewerEmail);
        expect(rows.map(r => r.binding_id)).not.toContain(f.revokedBinding);
        expect(byPrincipal.has(f.operator)).toBe(false);
    });

    it("adds inherited bindings on request, only where the actor can read them", async () => {
        const asOperator = await kit
            .as(f.operator)
            .listTenantBindings(f.tenantA, { includeInherited: true, limit: 1000 });

        expect(
            asOperator.rows.find(r => r.principal_id === f.operator),
        ).toMatchObject({ source_tenant_id: f.master, inherited: true });

        const asMember = await kit
            .as(f.member)
            .listTenantBindings(f.tenantA, { includeInherited: true });

        expect(asMember.rows.some(r => r.inherited)).toBe(false);
    });

    // As the role_bindings policy has it: your own grants are always visible to you.
    it("shows a member without authz.bindings.read only themselves", async () => {
        const { rows } = await kit.as(f.viewer).listTenantBindings(f.tenantA);

        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
            principal_id: f.viewer,
            email: f.viewerEmail,
            role_name: f.viewerRoleName,
        });
    });

    it("lists the roles in effect, flagging the inherited ones", async () => {
        const { rows } = await kit.as(f.member).listRoles(f.tenantA);
        const byName = new Map(rows.map(r => [r.name, r]));

        expect(byName.get("tenant_admin")).toMatchObject({
            role_id: TENANT_ADMIN_ROLE,
            inherited: true,
            source_tenant_id: f.master,
        });
        expect(byName.get("admin")?.crosses_boundary).toBe(true);
        expect(byName.get(f.viewerRoleName)).toMatchObject({
            role_id: f.viewerRole,
            inherited: false,
        });

        expect((await kit.as(f.viewer).listRoles(f.tenantA)).rows).toEqual([]);
    });

    it("lists what an inherited role confers to a tenant admin below its owner", async () => {
        const { rows } = await kit
            .as(f.member)
            .listRoleScopes(f.tenantA, TENANT_ADMIN_ROLE);
        const names = rows.map(r => r.name);

        expect(names).toHaveLength(13);
        expect(names).not.toContain("authz.users.write");
    });

    it("lists scope definitions in effect, own and inherited", async () => {
        const { rows } = await kit.as(f.member).listScopes(f.tenantA, { limit: 1000 });
        const byName = new Map(rows.map(r => [r.name, r]));

        expect(byName.get(`app.view.${f.suffix}`)).toMatchObject({
            scope_id: f.appScope,
            description: "View things",
            inherited: false,
        });
        expect(byName.get("authz.roles.read")?.inherited).toBe(true);
    });

    it("lists API keys without ever returning key_hash, and shows revocation", async () => {
        const as = kit.as(f.member);
        const label = `listed-${randomSuffix()}`;

        await as.createApiKey(f.tenantA, label);

        const before = (await as.listApiKeys(f.tenantA, { limit: 1000 })).rows.find(
            r => r.label === label,
        );

        expect(before).toBeDefined();
        expect(before).not.toHaveProperty("key_hash");
        expect(before?.revoked_at).toBeNull();

        await as.revokeApiKey(before?.api_key_id ?? "");

        const after = (await as.listApiKeys(f.tenantA, { limit: 1000 })).rows.find(
            r => r.label === label,
        );

        expect(after?.revoked_at).not.toBeNull();
    });

    it("rejects a malformed cursor as a usage error", async () => {
        await expect(
            kit.as(f.member).listRoles(f.tenantA, { after: "not-a-cursor" }),
        ).rejects.toThrow(AuthzUsageError);
    });

    it("returns nothing, rather than failing, for a principal that does not exist", async () => {
        const nobody = kit.as(randomUUID());

        expect(await nobody.getTenant(f.tenantA)).toBeNull();
        expect((await nobody.listMyBindings()).rows).toEqual([]);
        expect((await nobody.listRoles(f.tenantA)).rows).toEqual([]);
    });
});

/**
 * The reads answer the same visibility questions as the dormant RLS policies in 002. Where they
 * cover the same rows, they must agree.
 *
 * Checked the way the model doc describes: inside a transaction that is always rolled back,
 * claim the fixture identities with auth.users rows, temporarily grant `authenticated` what the
 * policies need, and read the tables as that role with a JWT's claims set. Only the row sets the
 * two genuinely share are compared -- the roles and scopes reads resolve through the chain on
 * purpose, where the policies gate each row on its owner.
 */
describe.skipIf(!databaseAvailable)("reads agree with the RLS policies", () => {
    let client: Client;
    let f: Fixture;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();
        f = await buildFixture(client);
    });

    afterAll(async () => {
        await client?.end();
    });

    async function ids(sql: string, params: unknown[]): Promise<string[]> {
        const { rows } = await client.query(sql, params);

        return rows.map(row => row.id as string).sort();
    }

    async function compareAs(actor: string, email: string) {
        await client.query("begin");

        try {
            const authUserId = randomUUID();

            await client.query(
                `insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, created_at, updated_at)
                 values ($1, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', $2, now(), now(), now())`,
                [authUserId, email],
            );

            // The reads, as the owner, in the same transaction and so over the same data.
            const fromFunctions = {
                children: await ids(
                    "select tenant_id as id from authz.list_child_tenants($1, $2, 1000)",
                    [actor, f.tenantA],
                ),
                apiKeys: await ids(
                    "select api_key_id as id from authz.list_api_keys($1, $2, 1000)",
                    [actor, f.tenantA],
                ),
                tenantBindings: await ids(
                    "select binding_id as id from authz.list_tenant_bindings($1, $2, false, 1000)",
                    [actor, f.tenantA],
                ),
                viewerBindings: await ids(
                    "select binding_id as id from authz.list_principal_bindings($1, $2, 1000)",
                    [actor, f.viewer],
                ),
            };

            await client.query(`
                grant usage on schema authz to authenticated;
                grant select on all tables in schema authz to authenticated;
                grant execute on function
                    authz.has_scope(uuid, uuid, text),
                    authz.current_principal_id(),
                    authz.can_read_user(uuid, uuid),
                    authz.can_read_principal(uuid, uuid),
                    authz.role_tenant_id(uuid),
                    authz.master_tenant_id()
                to authenticated;
            `);
            await client.query("set local role authenticated");
            await client.query("select set_config('request.jwt.claims', $1, true)", [
                JSON.stringify({ sub: authUserId, role: "authenticated" }),
            ]);

            // The policies apply the RLS rule; liveness is the reads' own filter, restated here
            // because a policy shows revoked rows too.
            const fromPolicies = {
                children: await ids("select id from authz.tenants where parent_id = $1", [
                    f.tenantA,
                ]),
                apiKeys: await ids("select id from authz.api_keys where tenant_id = $1", [
                    f.tenantA,
                ]),
                tenantBindings: await ids(
                    "select id from authz.role_bindings where tenant_id = $1 and revoked_at is null and (expires_at is null or expires_at > now())",
                    [f.tenantA],
                ),
                viewerBindings: await ids(
                    "select id from authz.role_bindings where principal_id = $1 and revoked_at is null and (expires_at is null or expires_at > now())",
                    [f.viewer],
                ),
            };

            return { fromFunctions, fromPolicies };
        } finally {
            await client.query("rollback");
        }
    }

    it("for a tenant admin", async () => {
        const { fromFunctions, fromPolicies } = await compareAs(f.member, f.memberEmail);

        expect(fromFunctions).toEqual(fromPolicies);
        // Guard against agreeing vacuously on empty sets.
        expect(fromFunctions.children.length).toBeGreaterThan(0);
        expect(fromFunctions.tenantBindings.length).toBeGreaterThan(0);
    });

    it("for a member with no authz read scopes", async () => {
        const { fromFunctions, fromPolicies } = await compareAs(f.viewer, f.viewerEmail);

        expect(fromFunctions).toEqual(fromPolicies);
        // Their own binding is the one thing both must show them.
        expect(fromFunctions.viewerBindings).toHaveLength(1);
        expect(fromFunctions.children).toEqual([]);
    });
});
