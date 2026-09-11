import { rethrowAsAuthKitError } from "./errors.js";
import { scalar, type QueryFn } from "./query.js";

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
    query: QueryFn,
    actorPrincipalId: string,
): WriteApi {
    async function returning(
        sql: string,
        params: readonly unknown[],
    ): Promise<string> {
        try {
            const value = await scalar<string>(query, sql, params);

            if (value === null) {
                throw new Error(`authz call returned no value: ${sql}`);
            }

            return value;
        } catch (error) {
            rethrowAsAuthKitError(error);
        }
    }

    async function voidCall(
        sql: string,
        params: readonly unknown[],
    ): Promise<void> {
        try {
            await query(sql, params);
        } catch (error) {
            rethrowAsAuthKitError(error);
        }
    }

    const actor = actorPrincipalId;

    return {
        grantRole: (principalId, roleId, tenantId, expiresAt = null) =>
            returning(
                "select authz.grant_role($1, $2, $3, $4, $5) as result",
                [actor, principalId, roleId, tenantId, expiresAt],
            ),

        inviteUser: (tenantId, email, roleId) =>
            returning("select authz.invite_user($1, $2, $3, $4) as result", [
                actor,
                tenantId,
                email,
                roleId,
            ]),

        revokeBinding: bindingId =>
            voidCall("select authz.revoke_binding($1, $2)", [actor, bindingId]),

        createRole: (tenantId, name, description, crossesBoundary = false) =>
            returning(
                "select authz.create_role($1, $2, $3, $4, $5) as result",
                [actor, tenantId, name, description, crossesBoundary],
            ),

        updateRole: (roleId, changes) =>
            voidCall("select authz.update_role($1, $2, $3, $4, $5)", [
                actor,
                roleId,
                changes.name ?? null,
                changes.description ?? null,
                changes.crossesBoundary ?? null,
            ]),

        addRoleScope: (roleId, scopeId) =>
            voidCall("select authz.add_role_scope($1, $2, $3)", [
                actor,
                roleId,
                scopeId,
            ]),

        removeRoleScope: (roleId, scopeId) =>
            voidCall("select authz.remove_role_scope($1, $2, $3)", [
                actor,
                roleId,
                scopeId,
            ]),

        createScope: (tenantId, name, description = null) =>
            returning("select authz.create_scope($1, $2, $3, $4) as result", [
                actor,
                tenantId,
                name,
                description,
            ]),

        createTenant: (parentId, name) =>
            returning("select authz.create_tenant($1, $2, $3) as result", [
                actor,
                parentId,
                name,
            ]),

        createWorkspace: name =>
            returning("select authz.create_workspace($1, $2) as result", [
                actor,
                name,
            ]),

        updateTenant: (tenantId, changes) =>
            voidCall("select authz.update_tenant($1, $2, $3, $4)", [
                actor,
                tenantId,
                changes.name ?? null,
                changes.inherit ?? null,
            ]),

        createApiKey: (tenantId, label, expiresAt = null) =>
            returning(
                "select authz.create_api_key($1, $2, $3, $4) as result",
                [actor, tenantId, label, expiresAt],
            ),

        revokeApiKey: apiKeyId =>
            voidCall("select authz.revoke_api_key($1, $2)", [actor, apiKeyId]),
    };
}
