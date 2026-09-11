import { column, scalar, type QueryFn } from "./query.js";

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
    query: QueryFn,
    principalId: string | null,
    tenantId: string | null,
    scope: string,
): Promise<boolean> {
    if (principalId === null || tenantId === null) {
        return false;
    }

    return (
        (await scalar<boolean>(
            query,
            "select authz.has_scope($1, $2, $3) as result",
            [principalId, tenantId, scope],
        )) === true
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
    query: QueryFn,
    principalId: string | null,
    tenantId: string | null,
): Promise<string[]> {
    if (principalId === null || tenantId === null) {
        return [];
    }

    return column<string>(
        query,
        "select scope_name as result from authz.effective_scopes($1, $2)",
        [principalId, tenantId],
    );
}
