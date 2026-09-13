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
}

export function createWriteApi(
    transport: AuthzTransport,
    actorPrincipalId: string,
): WriteApi {
    const actor = actorPrincipalId;

    async function returning(fn: AuthzFunction, args: RpcArgs): Promise<string> {
        const value = await transport.scalar(fn, {
            p_actor_principal_id: actor,
            ...args,
        });

        if (value === null) {
            throw new Error(`authz.${fn} returned no value`);
        }

        return value as string;
    }

    async function voidCall(fn: AuthzFunction, args: RpcArgs): Promise<void> {
        await transport.scalar(fn, { p_actor_principal_id: actor, ...args });
    }

    // Serialised here rather than left to each transport: pg would bind a Date natively, but
    // JSON would stringify it anyway, and one explicit form keeps the two identical.
    const timestamp = (value: Date | string | null): string | null =>
        value instanceof Date ? value.toISOString() : value;

    return {
        grantRole: (principalId, roleId, tenantId, expiresAt = null) =>
            returning("grant_role", {
                p_principal_id: principalId,
                p_role_id: roleId,
                p_tenant_id: tenantId,
                p_expires_at: timestamp(expiresAt),
            }),

        inviteUser: (tenantId, email, roleId) =>
            returning("invite_user", {
                p_tenant_id: tenantId,
                p_email: email,
                p_role_id: roleId,
            }),

        revokeBinding: bindingId =>
            voidCall("revoke_binding", { p_binding_id: bindingId }),

        createRole: (tenantId, name, description, crossesBoundary = false) =>
            returning("create_role", {
                p_tenant_id: tenantId,
                p_name: name,
                p_description: description,
                p_crosses_boundary: crossesBoundary,
            }),

        updateRole: (roleId, changes) =>
            voidCall("update_role", {
                p_role_id: roleId,
                p_name: changes.name ?? null,
                p_description: changes.description ?? null,
                p_crosses_boundary: changes.crossesBoundary ?? null,
            }),

        addRoleScope: (roleId, scopeId) =>
            voidCall("add_role_scope", { p_role_id: roleId, p_scope_id: scopeId }),

        removeRoleScope: (roleId, scopeId) =>
            voidCall("remove_role_scope", {
                p_role_id: roleId,
                p_scope_id: scopeId,
            }),

        createScope: (tenantId, name, description = null) =>
            returning("create_scope", {
                p_tenant_id: tenantId,
                p_name: name,
                p_description: description,
            }),

        createTenant: (parentId, name) =>
            returning("create_tenant", { p_parent_id: parentId, p_name: name }),

        createWorkspace: name => returning("create_workspace", { p_name: name }),

        updateTenant: (tenantId, changes) =>
            voidCall("update_tenant", {
                p_tenant_id: tenantId,
                p_name: changes.name ?? null,
                p_inherit: changes.inherit ?? null,
            }),

        createApiKey: (tenantId, label, expiresAt = null) =>
            returning("create_api_key", {
                p_tenant_id: tenantId,
                p_label: label,
                p_expires_at: timestamp(expiresAt),
            }),

        revokeApiKey: apiKeyId =>
            voidCall("revoke_api_key", { p_api_key_id: apiKeyId }),
    };
}
