/**
 * Audit logging against a real local Supabase stack, once per transport. Skipped when the stack
 * is unreachable.
 *
 * Three things only a live database can prove:
 *
 *   - a successful write logs itself **in the same transaction**, so the row and the change it
 *     describes cannot disagree;
 *   - a refused write still logs, from the caller, after the raise has rolled the function's own
 *     transaction back -- the case that motivated the feature and the one a unit test cannot
 *     reach, since it is Postgres's rollback that makes it necessary;
 *   - `list_audit_logs` answers exactly what the `audit_logs` policy would, which is the same
 *     parity `reads.integration.test.ts` holds for the other reads.
 */
import { randomUUID } from "node:crypto";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
    AuthzDeniedError,
    createAuthKit,
    fromQuery,
    type AuditLogRow,
} from "../../src/index.js";
import {
    DB_URL,
    TENANT_ADMIN_ROLE,
    TRANSPORTS,
    databaseAvailable,
    one,
} from "./stack.js";

describe.each(TRANSPORTS)("audit log against a live authz schema ($name)", transport => {
    if (!transport.available) {
        it.skip("needs a reachable local stack", () => {});

        return;
    }

    let client: Client;
    let kit: ReturnType<typeof createAuthKit>;

    const suffix = Math.random().toString(36).slice(2, 10);
    const operatorEmail = `atest-op-${suffix}@example.com`;
    const memberEmail = `atest-member-${suffix}@example.com`;

    let operatorPrincipal: string;
    let memberPrincipal: string;
    let tenantId: string;
    let masterId: string;

    const requestContext = {
        requestId: `req-${suffix}`,
        method: "POST",
        route: "/tenants/:id/roles",
        ip: "203.0.113.7",
        userAgent: "vitest",
    };

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();

        kit = createAuthKit({
            transport: transport.make(client),
            verifyBearer: async () => null,
        });

        masterId = await one<string>("select authz.master_tenant_id() as result", []);

        const operatorUser = await one<string>(
            "select authz.provision_admin($1) as result",
            [operatorEmail],
        );
        operatorPrincipal = await one<string>(
            "select p.id as result from authz.principals p where p.user_id = $1",
            [operatorUser],
        );

        tenantId = await kit
            .as(operatorPrincipal)
            .createTenant(masterId, `atest-${suffix}`);

        await kit.as(operatorPrincipal).inviteUser(tenantId, memberEmail, TENANT_ADMIN_ROLE);

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

    async function rowsFor(targetId: string): Promise<AuditLogRow[]> {
        const { rows } = await kit
            .as(operatorPrincipal)
            .listAuditLogs({ targetId, limit: 10 });

        return rows;
    }

    it("logs a successful write with its request context", async () => {
        const as = kit.as(memberPrincipal, requestContext);
        const roleId = await as.createRole(tenantId, `editor-${suffix}`, "Editor");

        const [row] = await rowsFor(roleId);

        expect(row).toMatchObject({
            action: "create_role",
            target_type: "role",
            target_id: roleId,
            tenant_id: tenantId,
            actor_principal_id: memberPrincipal,
            actor_kind: "user",
            outcome: "success",
            request_id: requestContext.requestId,
            method: "POST",
            route: "/tenants/:id/roles",
            ip: "203.0.113.7",
            user_agent: "vitest",
        });

        expect(row?.after).toMatchObject({ name: `editor-${suffix}` });
    });

    it("records a refusal, which the refusing function cannot do itself", async () => {
        const as = kit.as(memberPrincipal, requestContext);

        // A tenant admin holds no authz.roles.write at the master.
        await expect(
            as.createRole(masterId, `nope-${suffix}`, "Refused"),
        ).rejects.toBeInstanceOf(AuthzDeniedError);

        const { rows } = await kit.as(operatorPrincipal).listAuditLogs({
            tenantId: masterId,
            actorPrincipalId: memberPrincipal,
            outcome: "denied",
            limit: 10,
        });

        expect(rows[0]).toMatchObject({
            action: "create_role",
            outcome: "denied",
            tenant_id: masterId,
            actor_principal_id: memberPrincipal,
            request_id: requestContext.requestId,
        });

        // The refusal's own words, so the log says why and not merely that.
        expect(rows[0]?.reason).toContain("authz.roles.write");
    });

    it("never lets a denial's own arguments break the insert", async () => {
        // The tenant does not exist, so its foreign key cannot resolve. log_audit stores null
        // rather than raising: a foreign key violation here would turn a clean denial into a
        // 500, and on a successful write it would roll the write back.
        const ghost = "00000000-0000-4000-8000-0000000000ff";

        await expect(
            kit.as(memberPrincipal).createRole(ghost, `ghost-${suffix}`, "Nowhere"),
        ).rejects.toBeInstanceOf(AuthzDeniedError);

        const recorded = await one<number>(
            `select count(*)::int as result
               from authz.audit_logs
              where actor_principal_id = $1 and outcome = 'denied' and tenant_id is null`,
            [memberPrincipal],
        );

        expect(recorded).toBeGreaterThan(0);
    });

    it("pages newest first", async () => {
        const as = kit.as(operatorPrincipal);

        for (let i = 0; i < 3; i++) {
            await as.createRole(tenantId, `paged-${suffix}-${i}`, "Paged");
        }

        const first = await as.listAuditLogs({ tenantId, limit: 2 });

        expect(first.rows).toHaveLength(2);
        expect(first.nextCursor).not.toBeNull();
        expect(
            new Date(first.rows[0]!.created_at).getTime(),
        ).toBeGreaterThanOrEqual(new Date(first.rows[1]!.created_at).getTime());

        const second = await as.listAuditLogs({
            tenantId,
            limit: 2,
            after: first.nextCursor,
        });

        const overlap = second.rows.filter(row =>
            first.rows.some(seen => seen.audit_log_id === row.audit_log_id),
        );

        expect(overlap).toHaveLength(0);
    });

    it("shows a tenant's rows to nobody without audit.read there", async () => {
        // Refusal is filtering, never an exception: an outsider gets zero rows rather than an
        // error that would tell them the tenant exists.
        const outsiderEmail = `atest-out-${suffix}@example.com`;

        await kit.as(operatorPrincipal).inviteUser(
            await kit.as(operatorPrincipal).createTenant(masterId, `atest-other-${suffix}`),
            outsiderEmail,
            TENANT_ADMIN_ROLE,
        );

        const outsider = await one<string>(
            "select p.id as result from authz.principals p join authz.users u on u.id = p.user_id where u.email_id = authz.email_id($1)",
            [outsiderEmail],
        );

        const { rows } = await kit.as(outsider).listAuditLogs({ tenantId, limit: 10 });

        expect(rows).toEqual([]);
    });
});

/**
 * Two properties that are about Postgres rather than about the API, so they are checked once, on
 * the direct connection, rather than once per transport.
 */
describe.skipIf(!databaseAvailable)("audit rows and the database", () => {
    let client: Client;
    let kit: ReturnType<typeof createAuthKit>;

    const suffix = Math.random().toString(36).slice(2, 10);
    const email = `atx-op-${suffix}@example.com`;

    let actor: string;
    let tenantId: string;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        await client.connect();

        kit = createAuthKit({
            transport: fromQuery((sql, params) =>
                client.query(sql, params as unknown[]).then(r => r.rows),
            ),
            verifyBearer: async () => null,
        });

        const user = await one<string>(client, "select authz.provision_admin($1) as result", [
            email,
        ]);
        actor = await one<string>(
            client,
            "select p.id as result from authz.principals p where p.user_id = $1",
            [user],
        );
        tenantId = await kit
            .as(actor)
            .createTenant(
                await one<string>(client, "select authz.master_tenant_id() as result", []),
                `atx-${suffix}`,
            );
    });

    afterAll(async () => {
        await client?.end();
    });

    it("writes the row inside the transaction of the change it describes", async () => {
        // The whole argument for logging in SQL rather than from the caller: roll the write
        // back and its audit row goes with it. A row written over a second connection would
        // survive, and the trail would describe a change that never landed.
        await client.query("begin");

        const roleId = await kit
            .as(actor)
            .createRole(tenantId, `rollback-${suffix}`, "Rolled back");

        const inside = await one<number>(
            client,
            "select count(*)::int as result from authz.audit_logs where target_id = $1",
            [roleId],
        );

        await client.query("rollback");

        const after = await one<number>(
            client,
            "select count(*)::int as result from authz.audit_logs where target_id = $1",
            [roleId],
        );

        expect(inside).toBe(1);
        expect(after).toBe(0);
    });

    it("agrees with the audit_logs policy on which rows are visible", async () => {
        // The same parity the other reads hold, and the reason list_audit_logs exists rather
        // than a raw select: the function is the sanctioned read path under posture A, and it
        // must show exactly what RLS would show the same principal.
        const memberEmail = `atx-member-${suffix}@example.com`;

        await kit.as(actor).inviteUser(tenantId, memberEmail, TENANT_ADMIN_ROLE);

        const member = await one<string>(
            client,
            "select p.id as result from authz.principals p join authz.users u on u.id = p.user_id where u.email_id = authz.email_id($1)",
            [memberEmail],
        );

        await client.query("begin");

        try {
            const authUserId = randomUUID();

            await client.query(
                `insert into auth.users (id, instance_id, aud, role, email, email_confirmed_at, created_at, updated_at)
                 values ($1, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', $2, now(), now(), now())`,
                [authUserId, memberEmail],
            );
            await client.query(
                "update authz.users set auth_user_id = $1, claimed_at = now() where email_id = authz.email_id($2)",
                [authUserId, memberEmail],
            );

            const { rows: viaFunction } = await client.query<{ id: string }>(
                "select audit_log_id as id from authz.list_audit_logs($1, null, null, null, null, null, null, null, null, null, 1000)",
                [member],
            );

            await client.query(`
                grant usage on schema authz to authenticated;
                grant select on authz.audit_logs to authenticated;
                grant execute on function
                    authz.has_scope(uuid, uuid, text),
                    authz.current_principal_id(),
                    authz.master_tenant_id()
                to authenticated;
            `);
            await client.query("set local role authenticated");
            await client.query("select set_config('request.jwt.claims', $1, true)", [
                JSON.stringify({ sub: authUserId, role: "authenticated" }),
            ]);

            const { rows: viaPolicy } = await client.query<{ id: string }>(
                "select id from authz.audit_logs",
            );

            expect(new Set(viaPolicy.map(r => r.id))).toEqual(
                new Set(viaFunction.map(r => r.id)),
            );
            // Not vacuous: the invite and the tenant creation are in there.
            expect(viaFunction.length).toBeGreaterThan(0);
        } finally {
            await client.query("rollback");
        }
    });
});

/**
 * Pruning. Its concurrency story is the whole point -- a retention job runs on every replica of
 * a service -- so most of this needs two real connections and lives here rather than in a unit
 * test with a stubbed transport.
 */
describe.skipIf(!databaseAvailable)("pruning the audit log", () => {
    let client: Client;
    let other: Client;
    let kit: ReturnType<typeof createAuthKit>;

    const suffix = Math.random().toString(36).slice(2, 10);
    const email = `aprune-op-${suffix}@example.com`;

    let actor: string;
    let tenantId: string;

    beforeAll(async () => {
        client = new Client({ connectionString: DB_URL });
        other = new Client({ connectionString: DB_URL });
        await client.connect();
        await other.connect();

        kit = createAuthKit({
            transport: fromQuery((sql, params) =>
                client.query(sql, params as unknown[]).then(r => r.rows),
            ),
            verifyBearer: async () => null,
        });

        const user = await one<string>(client, "select authz.provision_admin($1) as result", [
            email,
        ]);
        actor = await one<string>(
            client,
            "select p.id as result from authz.principals p where p.user_id = $1",
            [user],
        );
        tenantId = await kit
            .as(actor)
            .createTenant(
                await one<string>(client, "select authz.master_tenant_id() as result", []),
                `aprune-${suffix}`,
            );
    });

    afterAll(async () => {
        await client?.end();
        await other?.end();
    });

    /** Scoped to the fixture's own tenant, so a shared local database cannot make these lie. */
    async function remaining(): Promise<number> {
        return one<number>(
            client,
            "select count(*)::int as result from authz.audit_logs where tenant_id = $1",
            [tenantId],
        );
    }

    // Role names are unique per tenant, so each batch needs its own token.
    let seeded = 0;

    async function seed(count: number, age: string): Promise<void> {
        const batch = seeded++;

        for (let i = 0; i < count; i++) {
            await kit
                .as(actor)
                .createRole(tenantId, `prune-${suffix}-${batch}-${i}`, "Prunable");
        }

        await client.query(
            `update authz.audit_logs set created_at = now() - $2::interval
              where tenant_id = $1 and created_at > now() - interval '1 hour'
                and action <> 'prune_audit_logs'`,
            [tenantId, age],
        );
    }

    it("deletes what is older than the cutoff and leaves the rest", async () => {
        await seed(3, "90 days");
        const old = await remaining();

        await kit.as(actor).createRole(tenantId, `keep-${suffix}`, "Recent");

        const { deleted_count, lock_acquired } = await kit.pruneAuditLogs({
            before: new Date(Date.now() - 30 * 86_400_000),
            tenantId,
        });

        expect(lock_acquired).toBe(true);
        expect(deleted_count).toBe(old);
        // The recent row survives, and so does the prune's own record.
        expect(await remaining()).toBeGreaterThan(0);
    });

    it("never deletes its own prune records", async () => {
        // The record of what was destroyed has to outlive the destruction: a trail with a hole
        // in it should be distinguishable from one that never had those rows.
        await client.query(
            `update authz.audit_logs set created_at = now() - interval '365 days'
              where tenant_id = $1`,
            [tenantId],
        );

        const { deleted_count } = await kit.pruneAuditLogs({
            before: new Date(),
            tenantId,
        });

        const { rows } = await client.query<{ action: string }>(
            "select action from authz.audit_logs where tenant_id = $1",
            [tenantId],
        );

        expect(deleted_count).toBeGreaterThan(0);
        expect(rows.length).toBeGreaterThan(0);
        expect(rows.every(r => r.action === "prune_audit_logs")).toBe(true);
    });

    it("logs the prune itself, with no actor", async () => {
        const { rows } = await client.query<{
            actor_principal_id: string | null;
            after: { deleted_count: number };
        }>(
            `select actor_principal_id, after from authz.audit_logs
              where tenant_id = $1 and action = 'prune_audit_logs'
              order by created_at desc limit 1`,
            [tenantId],
        );

        // Null rather than a stand-in principal: no principal did this, and naming one would
        // put a lie in the row.
        expect(rows[0]?.actor_principal_id).toBeNull();
        expect(rows[0]?.after.deleted_count).toBeGreaterThan(0);
    });

    it("writes no row when it deleted nothing", async () => {
        const before = await one<number>(
            client,
            `select count(*)::int as result from authz.audit_logs
              where tenant_id = $1 and action = 'prune_audit_logs'`,
            [tenantId],
        );

        const { deleted_count } = await kit.pruneAuditLogs({
            before: new Date(Date.now() - 365 * 86_400_000),
            tenantId,
        });

        const after = await one<number>(
            client,
            `select count(*)::int as result from authz.audit_logs
              where tenant_id = $1 and action = 'prune_audit_logs'`,
            [tenantId],
        );

        // A job on three replicas every five minutes would otherwise write more than it removes.
        expect(deleted_count).toBe(0);
        expect(after).toBe(before);
    });

    it("batches, so a loop can drain without one enormous transaction", async () => {
        await seed(5, "90 days");

        const cutoff = new Date(Date.now() - 30 * 86_400_000);
        let batches = 0;
        let total = 0;

        for (;;) {
            const { deleted_count, lock_acquired } = await kit.pruneAuditLogs({
                before: cutoff,
                tenantId,
                limit: 2,
            });

            expect(lock_acquired).toBe(true);
            batches++;
            total += deleted_count;

            if (deleted_count === 0 || batches > 10) break;
        }

        expect(total).toBeGreaterThanOrEqual(5);
        expect(batches).toBeGreaterThan(1);
    });

    it("single-flights across replicas, and says so rather than reporting nothing to do", async () => {
        await seed(4, "90 days");

        // Hold the advisory lock on a second connection, as another replica mid-batch would.
        // Transaction-scoped, so the rollback releases it even if this test fails.
        await other.query("begin");
        await other.query(
            "select pg_advisory_xact_lock(hashtext('authz.prune_audit_logs:' || $1::text))",
            [tenantId],
        );

        try {
            const result = await kit.pruneAuditLogs({
                before: new Date(Date.now() - 30 * 86_400_000),
                tenantId,
            });

            // Zero deleted, but emphatically not "nothing left to delete" -- four rows are
            // waiting. A loop keyed only on the count would stop here and never come back.
            expect(result).toEqual({ deleted_count: 0, lock_acquired: false });
            expect(await remaining()).toBeGreaterThan(0);
        } finally {
            await other.query("rollback");
        }

        // Released: the next caller gets the lock and the work.
        const after = await kit.pruneAuditLogs({
            before: new Date(Date.now() - 30 * 86_400_000),
            tenantId,
        });

        expect(after.lock_acquired).toBe(true);
        expect(after.deleted_count).toBeGreaterThan(0);
    });

    it("refuses a call with no cutoff rather than deleting everything", async () => {
        await expect(
            kit.pruneAuditLogs({ before: null as unknown as string }),
        ).rejects.toThrow();
    });
});
