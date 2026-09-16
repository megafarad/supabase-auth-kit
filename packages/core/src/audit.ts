import type { AuthzTransport } from "./transport.js";

/**
 * The HTTP context an audit row records alongside the change itself.
 *
 * Travels to SQL as one jsonb rather than five arguments -- a session GUC was not an option,
 * since the supabase-js transport cannot set one in the same transaction as the RPC it wraps,
 * and the two transports have to stay indistinguishable. Everything here is optional: a cron
 * job, a migration or a test has no request, and audit logging must never be the reason a write
 * fails.
 */
export interface RequestContext {
    /** Correlates the row with the application's own logs. Adapters supply or generate one. */
    requestId?: string | undefined;
    method?: string | undefined;
    /** The route pattern where the framework knows it, the raw path where it does not. */
    route?: string | undefined;
    ip?: string | undefined;
    userAgent?: string | undefined;
}

/** What actually happened, as one row. */
export interface AuditEntry {
    /** Omitted by `ActorApi.logAudit`, which binds the actor like every other call. */
    actorPrincipalId?: string | null | undefined;
    /**
     * Null means a platform-level event, readable only with `authz.audit.read` at the master --
     * the rule the `audit_logs` policy states with its coalesce. An id that does not resolve is
     * stored as null rather than raising, so a denial can always be recorded for the tenant that
     * was asked about even when that tenant does not exist.
     */
    tenantId?: string | null | undefined;
    action: string;
    targetType: string;
    targetId?: string | null | undefined;
    before?: unknown;
    after?: unknown;
    /** Defaults to `success`. */
    outcome?: AuditOutcome | undefined;
    /** The refusal's message on a denial. */
    reason?: string | null | undefined;
    requestContext?: RequestContext | null | undefined;
}

export type AuditOutcome = "success" | "denied";

/** One row of the trail. Column names, as everywhere. */
export interface AuditLogRow {
    audit_log_id: string;
    actor_principal_id: string | null;
    actor_kind: "user" | "api_key" | null;
    request_id: string | null;
    method: string | null;
    route: string | null;
    action: string;
    target_type: string;
    target_id: string | null;
    tenant_id: string | null;
    outcome: AuditOutcome;
    /** The refusal's message on a denied row, null otherwise. */
    reason: string | null;
    before: unknown;
    after: unknown;
    ip: string | null;
    user_agent: string | null;
    created_at: string;
}

/**
 * Every filter is optional and null-safe. Omitting `tenantId` is not "no tenant" but "every
 * tenant you may read", which is how a subtree is listed -- authority at a tenant covers its
 * descendants' rows, because `has_scope` resolves through the ancestor chain.
 */
export interface AuditFilter {
    tenantId?: string | null | undefined;
    actorPrincipalId?: string | null | undefined;
    action?: string | null | undefined;
    targetType?: string | null | undefined;
    targetId?: string | null | undefined;
    requestId?: string | null | undefined;
    outcome?: AuditOutcome | null | undefined;
    /** Inclusive. */
    from?: Date | string | null | undefined;
    /** Exclusive, so consecutive windows neither overlap nor drop a row. */
    to?: Date | string | null | undefined;
}

/** One batch of a retention run. */
export interface PruneOptions {
    /** Rows strictly older than this go. Required: a forgotten cutoff must not mean everything. */
    before: Date | string;
    /** Limits the prune to one tenant's rows. Omit for every row, tenantless ones included. */
    tenantId?: string | null | undefined;
    /** Rows per batch. Defaults to 1000 in SQL. */
    limit?: number | undefined;
}

/** Column names, as everywhere. */
export interface PruneResult {
    deleted_count: number;
    /**
     * False when another prune held the advisory lock, in which case nothing was examined.
     *
     * The distinction matters to the caller's loop: `deleted_count` is 0 both when there is
     * nothing left to delete and when someone else is already deleting it, and those two call
     * for opposite responses -- stop, or come back later.
     */
    lock_acquired: boolean;
}

/**
 * One batch of pruning. **Takes no actor**: retention is a maintenance job, authority is the
 * connection, and the SQL function has no actor parameter to pass one to.
 *
 * Loop until `deleted_count` is 0 with the lock held, sleeping between batches:
 *
 * ```ts
 * for (;;) {
 *     const { deleted_count, lock_acquired } = await kit.pruneAuditLogs({ before });
 *     if (!lock_acquired) break;          // another replica has it
 *     if (deleted_count === 0) break;     // nothing left
 *     await sleep(100);
 * }
 * ```
 */
export async function pruneAuditLogs(
    transport: AuthzTransport,
    options: PruneOptions,
): Promise<PruneResult> {
    const before =
        options.before instanceof Date ? options.before.toISOString() : options.before;

    const rows = await transport.rows("prune_audit_logs", {
        p_before: before,
        p_tenant_id: options.tenantId ?? null,
        p_limit: options.limit,
    });

    const row = rows[0];

    if (row === undefined) {
        throw new Error("authz.prune_audit_logs returned no row");
    }

    return {
        deleted_count: Number(row["deleted_count"]),
        lock_acquired: row["lock_acquired"] === true,
    };
}

/** The jsonb the SQL side reads. Keys are snake_case there, as everywhere. */
export function requestContextToJson(
    context: RequestContext | null | undefined,
): Record<string, string> | undefined {
    if (context === null || context === undefined) {
        return undefined;
    }

    const json: Record<string, string> = {};

    if (context.requestId !== undefined) json["request_id"] = context.requestId;
    if (context.method !== undefined) json["method"] = context.method;
    if (context.route !== undefined) json["route"] = context.route;
    if (context.ip !== undefined) json["ip"] = context.ip;
    if (context.userAgent !== undefined) json["user_agent"] = context.userAgent;

    // An empty object would still be stored, and would read as "there was a request, and we
    // know nothing about it". Undefined is omitted by both transports, so the column stays null.
    return Object.keys(json).length === 0 ? undefined : json;
}

/**
 * Appends one row. Resolves to the new row's id, or **null when the write failed**.
 *
 * Swallowing is the point, and it is the same rule the SQL side follows: audit logging must
 * never change the outcome of the thing it describes. Every caller here is either on an error
 * path already -- where a logging failure would mask the denial the caller actually needs to
 * see -- or inside a request whose real work has succeeded. The failure is not lost: it is
 * passed to `onError` if the kit was given one.
 */
export async function logAudit(
    transport: AuthzTransport,
    entry: AuditEntry,
    onError?: ((error: unknown) => void) | undefined,
): Promise<string | null> {
    try {
        const id = await transport.scalar("log_audit", {
            p_actor_principal_id: entry.actorPrincipalId ?? null,
            p_tenant_id: entry.tenantId ?? null,
            p_action: entry.action,
            p_target_type: entry.targetType,
            p_target_id: entry.targetId ?? null,
            p_before: entry.before ?? null,
            p_after: entry.after ?? null,
            p_outcome: entry.outcome ?? "success",
            p_reason: entry.reason ?? null,
            p_request_ctx: requestContextToJson(entry.requestContext) ?? null,
        });

        return (id as string | null) ?? null;
    } catch (error) {
        onError?.(error);

        return null;
    }
}
