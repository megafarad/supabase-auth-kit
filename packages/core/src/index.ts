import { effectiveScopes, hasScope } from "./authorize.js";
import {
    createBearerVerifier,
    principalForApiKey,
    principalForAuthUser,
    principalIsActive,
    type JwtOptions,
    type VerifyBearer,
} from "./identity.js";
import type { QueryFn } from "./query.js";
import { createWriteApi, type WriteApi } from "./writes.js";

export type { QueryFn, Row } from "./query.js";
export type { JwtOptions, VerifyBearer } from "./identity.js";
export type { WriteApi } from "./writes.js";
export { isUuid } from "./uuid.js";
export {
    AuthKitError,
    AuthzConflictError,
    AuthzDeniedError,
    AuthzStateError,
    AuthzUsageError,
} from "./errors.js";

// The HTTP layer shared by the framework bindings. Framework-agnostic by construction -- nothing
// below imports Express or Fastify -- and kept here so the guard order exists exactly once.
export {
    ForbiddenError,
    HttpAuthzError,
    MiddlewareNotInstalledError,
    TenantRequiredError,
    UnauthenticatedError,
    statusOf,
} from "./http-errors.js";
export { createAuthzContext, type AuthzContext } from "./context.js";
export {
    checkAllScopes,
    checkAnyScope,
    checkScope,
    enforceGuard,
    type GuardCheck,
} from "./guard.js";
export { credentialsFromHeaders, type HeaderBag } from "./headers.js";
export {
    tenantFromBody,
    tenantFromHeader,
    tenantFromParam,
    tenantFromQuery,
    type TenantResolver,
    type TenantSource,
} from "./tenant.js";

export type PrincipalKind = "user" | "api_key";

/**
 * The outcome of resolving a request's credentials.
 *
 * `credentialPresented` is deliberately separate from `principalId`, because the two nulls mean
 * different things and callers must answer them differently. No credential at all is "who are
 * you" -- a 401. A credential that verified but resolved to no principal is a real, reachable
 * state -- someone who registered an address a retired identity still holds -- and that caller
 * is authenticated with zero authority, which is a 403. Collapsing them loses that.
 */
export interface ResolvedPrincipal {
    principalId: string | null;
    kind: PrincipalKind | null;
    credentialPresented: boolean;
}

export interface Credentials {
    /** A Supabase access token, without the `Bearer ` prefix. */
    bearer?: string | null | undefined;
    /** A plaintext API key as issued by `authz.create_api_key`. */
    apiKey?: string | null | undefined;
}

export interface AuthKitOptions {
    query: QueryFn;
    /**
     * JWKS-based verification against Supabase's endpoint. Required unless `verifyBearer` is
     * supplied instead.
     */
    jwt?: JwtOptions;
    /**
     * Bring your own token verification, returning the `auth.users` id or null. Takes
     * precedence over `jwt`. Use this when the app already verifies tokens some other way --
     * `supabase.auth.getUser(token)`, an upstream gateway -- so verification is not done twice.
     */
    verifyBearer?: VerifyBearer;
}

export interface AuthKit {
    /** Verifies a Supabase access token, returning its `auth.users` id or null. */
    verifyBearer(token: string): Promise<string | null>;
    principalForAuthUser(authUserId: string): Promise<string | null>;
    principalForApiKey(key: string): Promise<string | null>;
    principalIsActive(principalId: string): Promise<boolean>;
    /** API key first, then bearer token. Shared by every framework binding. */
    resolvePrincipal(credentials: Credentials): Promise<ResolvedPrincipal>;
    hasScope(
        principalId: string | null,
        tenantId: string | null,
        scope: string,
    ): Promise<boolean>;
    effectiveScopes(
        principalId: string | null,
        tenantId: string | null,
    ): Promise<string[]>;
    /**
     * The write API with this actor pre-bound. Take it once per request, from the resolved
     * principal, so the wrong actor cannot be threaded into a call by hand.
     */
    as(actorPrincipalId: string): WriteApi;
}

export function createAuthKit(options: AuthKitOptions): AuthKit {
    const { query } = options;

    const verifyBearer =
        options.verifyBearer ??
        (options.jwt === undefined
            ? undefined
            : createBearerVerifier(options.jwt));

    if (verifyBearer === undefined) {
        throw new TypeError(
            "createAuthKit requires either `jwt` or `verifyBearer`",
        );
    }

    return {
        verifyBearer,

        principalForAuthUser: authUserId =>
            principalForAuthUser(query, authUserId),

        principalForApiKey: key => principalForApiKey(query, key),

        principalIsActive: principalId => principalIsActive(query, principalId),

        async resolvePrincipal({ bearer, apiKey }) {
            // An API key wins when both are sent, so verify_api_key runs at most once and a
            // request never pays for two identity round trips.
            if (apiKey) {
                const principalId = await principalForApiKey(query, apiKey);

                return {
                    principalId,
                    kind: principalId === null ? null : "api_key",
                    credentialPresented: true,
                };
            }

            if (bearer) {
                const authUserId = await verifyBearer(bearer);

                const principalId =
                    authUserId === null
                        ? null
                        : await principalForAuthUser(query, authUserId);

                return {
                    principalId,
                    kind: principalId === null ? null : "user",
                    credentialPresented: true,
                };
            }

            return {
                principalId: null,
                kind: null,
                credentialPresented: false,
            };
        },

        hasScope: (principalId, tenantId, scope) =>
            hasScope(query, principalId, tenantId, scope),

        effectiveScopes: (principalId, tenantId) =>
            effectiveScopes(query, principalId, tenantId),

        as: actorPrincipalId => createWriteApi(query, actorPrincipalId),
    };
}
