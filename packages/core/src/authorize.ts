import type { AuthzTransport } from "./transport.js";

/**
 * Whether a principal holds a scope at a tenant.
 *
 * A null principal or tenant returns false rather than skipping the check. Both are reachable
 * states -- an authenticated user with no authz identity, or a request the tenant hook could
 * not resolve -- and neither is an error. SQL agrees: `has_scope(null, ...)` is also false, so
 * the short circuit here is an optimisation of the same answer, not a second rule. There is a
 * test asserting the two cannot diverge.
 *
 * The ancestor walk, the `inherit = false` filter and the `crosses_boundary` exemption all
 * live in `authz.tenant_chain`. Never re-derive any of it here.
 */
export async function hasScope(
    transport: AuthzTransport,
    principalId: string | null,
    tenantId: string | null,
    scope: string,
): Promise<boolean> {
    if (principalId === null || tenantId === null) {
        return false;
    }

    return (
        (await transport.scalar("has_scope", {
            p_principal_id: principalId,
            p_tenant_id: tenantId,
            p_scope: scope,
        })) === true
    );
}

/**
 * Every scope name a principal holds at a tenant. Empty for a null principal or tenant, for
 * the same reason `hasScope` returns false.
 *
 * Scope names are SQL identifiers used verbatim (`crosses_boundary`, not `crossesBoundary`) --
 * there is no camelCase mapping layer anywhere in the kit.
 */
export async function effectiveScopes(
    transport: AuthzTransport,
    principalId: string | null,
    tenantId: string | null,
): Promise<string[]> {
    if (principalId === null || tenantId === null) {
        return [];
    }

    const rows = await transport.rows("effective_scopes", {
        p_principal_id: principalId,
        p_tenant_id: tenantId,
    });

    return rows.map(row => row["scope_name"] as string);
}
