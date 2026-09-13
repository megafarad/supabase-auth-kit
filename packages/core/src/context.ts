import type { ActorApi, AuthKit, PrincipalKind, ResolvedPrincipal } from "./index.js";

/** What a framework binding attaches to a request once its credentials are resolved. */
export interface AuthzContext {
    readonly principalId: string | null;
    readonly kind: PrincipalKind | null;
    /** Whether the request carried a credential at all, however it resolved. */
    readonly credentialPresented: boolean;
    /** Every scope held at a tenant. Memoized per request, per tenant. */
    scopes(tenantId: string): Promise<ReadonlySet<string>>;
    has(tenantId: string, scope: string): Promise<boolean>;
    /**
     * The read and write APIs with this request's principal pre-bound, or null when there is no
     * principal.
     *
     * Null rather than a throwing stub so the type system carries the rule: you have to be
     * somebody before you can read or write, and there is no actor to pass if you are not.
     */
    readonly as: ActorApi | null;
}

/**
 * Builds one request's context. Call it once per request: the memo it holds is the only scope
 * cache in the kit, and it must never outlive the request -- see `packages/core/CLAUDE.md` on
 * why revocation rules out a cross-request cache.
 */
export function createAuthzContext(
    kit: AuthKit,
    { principalId, kind, credentialPresented }: ResolvedPrincipal,
): AuthzContext {
    // Promises, not resolved values: five concurrent has() calls in one tick must coalesce
    // into a single query. Caching the value only dedupes sequential calls.
    const memo = new Map<string, Promise<ReadonlySet<string>>>();

    const scopes = (tenantId: string): Promise<ReadonlySet<string>> => {
        const cached = memo.get(tenantId);

        if (cached !== undefined) {
            return cached;
        }

        const pending = kit
            .effectiveScopes(principalId, tenantId)
            .then(names => new Set(names) as ReadonlySet<string>);

        memo.set(tenantId, pending);

        return pending;
    };

    return {
        principalId,
        kind,
        credentialPresented,
        scopes,

        // Answered from the memoized set rather than authz.has_scope. The two are equivalent
        // by construction -- has_scope is an EXISTS over effective_scopes, the same traversal
        // at the same cost -- so fetching the set is strictly more information per round trip
        // and turns N checks against one tenant into one query. The traversal itself still
        // happens only in SQL.
        has: async (tenantId, scope) => (await scopes(tenantId)).has(scope),

        as: principalId === null ? null : kit.as(principalId),
    };
}
