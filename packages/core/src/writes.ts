import {
    logAudit,
    requestContextToJson,
    type AuditEntry,
    type RequestContext,
} from "./audit.js";
import { AuthzDeniedError } from "./errors.js";
import type { AuthzFunction, AuthzTransport, RpcArgs } from "./transport.js";

/**
 * The thirteen mutating functions, with the actor pre-bound.
 *
 * Binding the actor at construction is the point: the SQL functions take it as their first
 * argument precisely so nothing reads the JWT, and a caller who has to remember to thread it
 * through by hand will eventually thread the wrong one. Bind it once, at the moment the request's
 * principal is resolved, and the wrong actor becomes unrepresentable.
 *
 * Every guard lives in SQL. Nothing here re-checks authority, because a check in TypeScript
 * would be a second opinion that can disagree with the enforcing one.
 */
export interface WriteApi {
    /** Binds a principal to a role at a tenant, reinstating a revoked binding. Returns the binding id. */
    grantRole(
        principalId: string,
        roleId: string,
        tenantId: string,
        expiresAt?: Date | string | null,
    ): Promise<string>;

    /** Adds an address to a tenant, provisioning an unclaimed identity if needed. Returns the authz user id. */
    inviteUser(tenantId: string, email: string, roleId: string): Promise<string>;

    /** Revokes a binding by timestamp. Idempotent; never deletes. */
    revokeBinding(bindingId: string): Promise<void>;

    /** Creates a role. `crossesBoundary` additionally requires roles.write at the master. */
    createRole(
        tenantId: string,
        name: string,
        description: string,
        crossesBoundary?: boolean,
    ): Promise<string>;

    /** Amends a role. Omitted fields are left alone; changing `crossesBoundary` is master-gated. */
    updateRole(
        roleId: string,
        changes: {
            name?: string | null;
            description?: string | null;
            crossesBoundary?: boolean | null;
        },
    ): Promise<void>;

    /** Attaches a scope. Refuses a scope the actor does not hold and does not own. */
    addRoleScope(roleId: string, scopeId: string): Promise<void>;

    /** Detaches a scope. Narrowing needs no holds-it check. */
    removeRoleScope(roleId: string, scopeId: string): Promise<void>;

    /** Creates a scope. The reserved `authz.` namespace is master-only. */
    createScope(
        tenantId: string,
        name: string,
        description?: string | null,
    ): Promise<string>;

    /** Creates a child tenant. Grants nothing: the actor's binding already reaches it. */
    createTenant(parentId: string, name: string): Promise<string>;

    /** Creates a top-level workspace under the master and self-grants tenant_admin. */
    createWorkspace(name: string): Promise<string>;

    /** Amends a tenant. Renaming needs write here; `inherit` needs it at the parent. */
    updateTenant(
        tenantId: string,
        changes: { name?: string | null; inherit?: boolean | null },
    ): Promise<void>;

    /** Issues an API key and returns the plaintext **once**. Only the hash is stored. */
    createApiKey(
        tenantId: string,
        label: string,
        expiresAt?: Date | string | null,
    ): Promise<string>;

    /** Revokes an API key by timestamp. Every binding its principal held goes with it. */
    revokeApiKey(apiKeyId: string): Promise<void>;

    /**
     * Appends a row to the audit log as this actor.
     *
     * The thirteen writes above already log themselves, inside their own transaction, so this
     * is for what they cannot: an event of the application's own, and -- the reason it exists --
     * a refusal. Both are recorded automatically when the kit is doing the refusing; call this
     * directly for a denial your own code decided.
     *
     * Never throws and never returns a rejected promise: it resolves to the new row's id, or
     * null if the write failed. A logging failure must not become the caller's problem.
     */
    logAudit(entry: Omit<AuditEntry, "actorPrincipalId">): Promise<string | null>;
}

/** What a refused call was trying to do, for the audit row the refusal itself cannot write. */
interface Attempt {
    targetType: string;
    targetId?: string | null | undefined;
    /**
     * Only where the caller's own arguments name it. Several writes are anchored on a tenant
     * that lives on the row being changed -- `revoke_binding` on the binding's tenant,
     * `update_role` on the role's -- which TypeScript would have to query for, and a query on
     * the denial path is a second chance to fail. Those denials are recorded with no tenant,
     * making them platform-level rows: readable with `authz.audit.read` at the master, and
     * deliberately not by the tenant admin whose call was refused.
     */
    tenantId?: string | null | undefined;
}

export interface WriteApiOptions {
    requestContext?: RequestContext | null | undefined;
    /** Whether a refused write records a denied row. Default true. */
    auditDenials?: boolean | undefined;
    onAuditError?: ((error: unknown) => void) | undefined;
}

export function createWriteApi(
    transport: AuthzTransport,
    actorPrincipalId: string,
    options: WriteApiOptions = {},
): WriteApi {
    const actor = actorPrincipalId;
    const requestContext = options.requestContext ?? null;
    const auditDenials = options.auditDenials ?? true;
    const onAuditError = options.onAuditError;

    // Built once: the same object goes to every call of this request, and it is already in the
    // shape SQL reads.
    const requestCtx = requestContextToJson(requestContext);

    /**
     * A refusal cannot log itself. Every guard in SQL signals with `raise exception`, which
     * rolls back the transaction and any audit row written inside it, and Postgres has no
     * autonomous transaction to escape that -- so the denied row is written here, afterwards,
     * from the one place that knows both what was attempted and that it was refused.
     *
     * The original error is always what propagates. `logAudit` resolves rather than rejects, so
     * a failure to record the denial cannot replace the denial itself.
     */
    async function call(
        fn: AuthzFunction,
        args: RpcArgs,
        attempt: Attempt,
    ): Promise<unknown> {
        try {
            return await transport.scalar(fn, {
                p_actor_principal_id: actor,
                ...args,
                p_request_ctx: requestCtx,
            });
        } catch (error) {
            if (auditDenials && error instanceof AuthzDeniedError) {
                await logAudit(
                    transport,
                    {
                        actorPrincipalId: actor,
                        tenantId: attempt.tenantId ?? null,
                        action: fn,
                        targetType: attempt.targetType,
                        targetId: attempt.targetId ?? null,
                        outcome: "denied",
                        reason: error.message,
                        requestContext,
                    },
                    onAuditError,
                );
            }

            throw error;
        }
    }

    async function returning(
        fn: AuthzFunction,
        args: RpcArgs,
        attempt: Attempt,
    ): Promise<string> {
        const value = await call(fn, args, attempt);

        if (value === null) {
            throw new Error(`authz.${fn} returned no value`);
        }

        return value as string;
    }

    async function voidCall(
        fn: AuthzFunction,
        args: RpcArgs,
        attempt: Attempt,
    ): Promise<void> {
        await call(fn, args, attempt);
    }

    // Serialised here rather than left to each transport: pg would bind a Date natively, but
    // JSON would stringify it anyway, and one explicit form keeps the two identical.
    const timestamp = (value: Date | string | null): string | null =>
        value instanceof Date ? value.toISOString() : value;

    return {
        grantRole: (principalId, roleId, tenantId, expiresAt = null) =>
            returning(
                "grant_role",
                {
                    p_principal_id: principalId,
                    p_role_id: roleId,
                    p_tenant_id: tenantId,
                    p_expires_at: timestamp(expiresAt),
                },
                { targetType: "role_binding", tenantId },
            ),

        inviteUser: (tenantId, email, roleId) =>
            returning(
                "invite_user",
                {
                    p_tenant_id: tenantId,
                    p_email: email,
                    p_role_id: roleId,
                },
                // The address is deliberately not in the denied row. A refusal here is often
                // exactly the retired-identity probe invite_user is ordered to prevent, and
                // writing the address into a readable table would hand back what the ordering
                // was protecting. The successful path records it; the refused one does not.
                { targetType: "user", tenantId },
            ),

        revokeBinding: bindingId =>
            voidCall(
                "revoke_binding",
                { p_binding_id: bindingId },
                { targetType: "role_binding", targetId: bindingId },
            ),

        createRole: (tenantId, name, description, crossesBoundary = false) =>
            returning(
                "create_role",
                {
                    p_tenant_id: tenantId,
                    p_name: name,
                    p_description: description,
                    p_crosses_boundary: crossesBoundary,
                },
                { targetType: "role", tenantId },
            ),

        updateRole: (roleId, changes) =>
            voidCall(
                "update_role",
                {
                    p_role_id: roleId,
                    p_name: changes.name ?? null,
                    p_description: changes.description ?? null,
                    p_crosses_boundary: changes.crossesBoundary ?? null,
                },
                { targetType: "role", targetId: roleId },
            ),

        addRoleScope: (roleId, scopeId) =>
            voidCall(
                "add_role_scope",
                { p_role_id: roleId, p_scope_id: scopeId },
                { targetType: "role", targetId: roleId },
            ),

        removeRoleScope: (roleId, scopeId) =>
            voidCall(
                "remove_role_scope",
                { p_role_id: roleId, p_scope_id: scopeId },
                { targetType: "role", targetId: roleId },
            ),

        createScope: (tenantId, name, description = null) =>
            returning(
                "create_scope",
                {
                    p_tenant_id: tenantId,
                    p_name: name,
                    p_description: description,
                },
                { targetType: "scope", tenantId },
            ),

        createTenant: (parentId, name) =>
            returning(
                "create_tenant",
                { p_parent_id: parentId, p_name: name },
                // Anchored on the parent, which is where the authority was missing. The child
                // does not exist to anchor on.
                { targetType: "tenant", targetId: parentId, tenantId: parentId },
            ),

        createWorkspace: name =>
            returning(
                "create_workspace",
                { p_name: name },
                { targetType: "tenant" },
            ),

        updateTenant: (tenantId, changes) =>
            voidCall(
                "update_tenant",
                {
                    p_tenant_id: tenantId,
                    p_name: changes.name ?? null,
                    p_inherit: changes.inherit ?? null,
                },
                { targetType: "tenant", targetId: tenantId, tenantId },
            ),

        createApiKey: (tenantId, label, expiresAt = null) =>
            returning(
                "create_api_key",
                {
                    p_tenant_id: tenantId,
                    p_label: label,
                    p_expires_at: timestamp(expiresAt),
                },
                { targetType: "api_key", tenantId },
            ),

        revokeApiKey: apiKeyId =>
            voidCall(
                "revoke_api_key",
                { p_api_key_id: apiKeyId },
                { targetType: "api_key", targetId: apiKeyId },
            ),

        logAudit: entry =>
            logAudit(
                transport,
                {
                    ...entry,
                    actorPrincipalId: actor,
                    // The request's context by default, since that is the whole reason it was
                    // bound here; an entry that names its own wins, for an event that did not
                    // happen on this request.
                    requestContext: entry.requestContext ?? requestContext,
                },
                onAuditError,
            ),
    };
}
