import { AuthzUsageError } from "./errors.js";
import type { Row } from "./query.js";
import type { AuthzFunction, AuthzTransport, RpcArgs } from "./transport.js";
import { isUuid } from "./uuid.js";

/**
 * Keyset paging. `after` is the `nextCursor` of the previous page; treat it as opaque.
 *
 * `limit` defaults to 100 and SQL clamps it to [1, 1000]. The ceiling is not arbitrary:
 * PostgREST truncates any RPC result at `max_rows` (1000 by default) without saying so, which is
 * why every list pages rather than returning everything.
 */
export interface PageOptions {
    limit?: number | undefined;
    after?: string | null | undefined;
}

export interface Page<T> {
    rows: T[];
    /**
     * Pass as `after` for the next page, or null when this page came back short. A page that
     * happens to end exactly at the last row still yields a cursor, and the page after it is
     * empty.
     */
    nextCursor: string | null;
}

/** All timestamps are ISO-8601 strings, whichever transport fetched them. */
export interface TenantRow {
    tenant_id: string;
    parent_id: string | null;
    name: string;
    inherit: boolean;
    created_at: string;
    updated_at: string;
}

/** A binding as seen from its principal. */
export interface PrincipalBindingRow {
    binding_id: string;
    principal_id: string;
    tenant_id: string;
    /** Null unless the binding is the actor's own or the actor holds `authz.tenants.read` there. */
    tenant_name: string | null;
    role_id: string;
    /** Null unless the binding is the actor's own or the actor holds `authz.roles.read` there. */
    role_name: string | null;
    granted_by_principal_id: string;
    granted_at: string;
    expires_at: string | null;
}

/** A binding as seen from a tenant: one of its members. */
export interface TenantBindingRow {
    binding_id: string;
    principal_id: string;
    principal_kind: "user" | "api_key";
    user_id: string | null;
    /** Null unless the actor holds `authz.users.read` where the binding was made. */
    email: string | null;
    /** Whether a Supabase account is attached. False for a pending invite; null for an API key. */
    claimed: boolean | null;
    api_key_id: string | null;
    /** Null unless the actor holds `authz.api_keys.read` at the key's tenant. */
    api_key_label: string | null;
    role_id: string;
    /** Null unless the actor holds `authz.roles.read` where the binding was made. */
    role_name: string | null;
    /** The tenant the binding was made at. */
    source_tenant_id: string;
    /** True when the binding was made above the tenant being listed. */
    inherited: boolean;
    granted_by_principal_id: string;
    granted_at: string;
    expires_at: string | null;
}

export interface RoleRow {
    role_id: string;
    name: string;
    description: string;
    crosses_boundary: boolean;
    source_tenant_id: string;
    inherited: boolean;
}

export interface RoleScopeRow {
    scope_id: string;
    name: string;
    description: string | null;
    source_tenant_id: string;
}

export interface ScopeRow {
    scope_id: string;
    name: string;
    description: string | null;
    source_tenant_id: string;
    inherited: boolean;
}

/** Never carries `key_hash`: the SQL does not return it. */
export interface ApiKeyRow {
    api_key_id: string;
    principal_id: string;
    key_prefix: string;
    label: string;
    tenant_id: string;
    created_by_user_id: string;
    last_used_at: string | null;
    expires_at: string | null;
    revoked_at: string | null;
    created_at: string;
}

/**
 * The read functions, with the actor pre-bound for the same reason as the writes.
 *
 * Refusal is an empty result, never an error: an actor without the authority sees nothing, as
 * RLS would show them, so a read cannot probe whether something exists. Every rule is in SQL.
 */
export interface ReadApi {
    /** The tenant, or null without `authz.tenants.read` there. */
    getTenant(tenantId: string): Promise<TenantRow | null>;

    /**
     * Children the actor holds `authz.tenants.read` at, by name. Meant for administrators of the
     * parent -- to find the tenants you belong to, use `listMyBindings`.
     */
    listChildTenants(parentId: string, page?: PageOptions): Promise<Page<TenantRow>>;

    /** The actor's own live bindings, by tenant name. How a tenant switcher finds your tenants. */
    listMyBindings(page?: PageOptions): Promise<Page<PrincipalBindingRow>>;

    /** A principal's live bindings, limited to tenants where the actor holds `authz.bindings.read`. */
    listPrincipalBindings(
        principalId: string,
        page?: PageOptions,
    ): Promise<Page<PrincipalBindingRow>>;

    /**
     * A tenant's members: its live bindings, by email or key label, including pending invites.
     * `includeInherited` adds bindings made above the tenant -- platform operators among them --
     * each still subject to `authz.bindings.read` where it was made.
     */
    listTenantBindings(
        tenantId: string,
        options?: PageOptions & { includeInherited?: boolean | undefined },
    ): Promise<Page<TenantBindingRow>>;

    /** Roles in effect at the tenant after shadowing. Needs `authz.roles.read` there. */
    listRoles(tenantId: string, page?: PageOptions): Promise<Page<RoleRow>>;

    /** The scopes a role in effect at the tenant confers. Needs `authz.roles.read` there. */
    listRoleScopes(
        tenantId: string,
        roleId: string,
        page?: PageOptions,
    ): Promise<Page<RoleScopeRow>>;

    /** Scope definitions in effect at the tenant after shadowing. Needs `authz.scopes.read` there. */
    listScopes(tenantId: string, page?: PageOptions): Promise<Page<ScopeRow>>;

    /** API keys issued at the tenant, revoked ones included. Needs `authz.api_keys.read` there. */
    listApiKeys(tenantId: string, page?: PageOptions): Promise<Page<ApiKeyRow>>;
}

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;

export function createReadApi(
    transport: AuthzTransport,
    actorPrincipalId: string,
): ReadApi {
    const actor = actorPrincipalId;

    async function page<T>(
        fn: AuthzFunction,
        args: RpcArgs,
        options: PageOptions | undefined,
    ): Promise<Page<T>> {
        // The same clamp SQL applies, done here too so the page size is known for certain when
        // deciding whether a page came back full, and so a fractional limit is not a cast error.
        const requested = options?.limit ?? DEFAULT_LIMIT;
        const limit = Number.isFinite(requested)
            ? Math.min(Math.max(Math.trunc(requested), 1), MAX_LIMIT)
            : DEFAULT_LIMIT;

        const after = options?.after ?? undefined;

        // SQL cannot be relied on to reject a bad cursor: it compares the sort key first, and
        // only casts the id half when the keys tie, so garbage usually just filters silently.
        if (after !== undefined && !isUuid(after.slice(0, 36))) {
            throw new AuthzUsageError("malformed page cursor");
        }

        const rows = await transport.rows(fn, {
            p_actor_principal_id: actor,
            ...args,
            p_limit: limit,
            p_after: after,
        });

        const last = rows.at(-1);

        return {
            rows: rows.map(stripCursor) as T[],
            nextCursor:
                rows.length >= limit && last !== undefined
                    ? (last["page_cursor"] as string)
                    : null,
        };
    }

    return {
        async getTenant(tenantId) {
            const rows = await transport.rows("get_tenant", {
                p_actor_principal_id: actor,
                p_tenant_id: tenantId,
            });

            return (rows[0] as unknown as TenantRow | undefined) ?? null;
        },

        listChildTenants: (parentId, options) =>
            page("list_child_tenants", { p_parent_id: parentId }, options),

        listMyBindings: options =>
            page("list_principal_bindings", { p_principal_id: actor }, options),

        listPrincipalBindings: (principalId, options) =>
            page("list_principal_bindings", { p_principal_id: principalId }, options),

        listTenantBindings: (tenantId, options) =>
            page(
                "list_tenant_bindings",
                {
                    p_tenant_id: tenantId,
                    p_include_inherited: options?.includeInherited ?? false,
                },
                options,
            ),

        listRoles: (tenantId, options) =>
            page("list_roles", { p_tenant_id: tenantId }, options),

        listRoleScopes: (tenantId, roleId, options) =>
            page(
                "list_role_scopes",
                { p_tenant_id: tenantId, p_role_id: roleId },
                options,
            ),

        listScopes: (tenantId, options) =>
            page("list_scopes", { p_tenant_id: tenantId }, options),

        listApiKeys: (tenantId, options) =>
            page("list_api_keys", { p_tenant_id: tenantId }, options),
    };
}

function stripCursor(row: Row): Row {
    const { page_cursor: _cursor, ...rest } = row;

    return rest;
}
