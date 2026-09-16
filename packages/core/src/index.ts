import {
    logAudit,
    pruneAuditLogs,
    type AuditEntry,
    type PruneOptions,
    type PruneResult,
    type RequestContext,
} from "./audit.js";
import { effectiveScopes, hasScope } from "./authorize.js";
import { rethrowAsAuthKitError } from "./errors.js";
import {
    createBearerVerifier,
    principalForApiKey,
    principalForAuthUser,
    principalIsActive,
    type JwtOptions,
    type VerifyBearer,
} from "./identity.js";
import type { QueryFn } from "./query.js";
import { createReadApi, type ReadApi } from "./reads.js";
import {
    fromQuery,
    fromSupabase,
    type AuthzTransport,
    type SupabaseRpcClient,
} from "./transport.js";
import { createWriteApi, type WriteApi } from "./writes.js";

export type { QueryFn, Row } from "./query.js";
export type { JwtOptions, VerifyBearer } from "./identity.js";
export type { WriteApi, WriteApiOptions } from "./writes.js";
export type {
    AuditEntry,
    AuditFilter,
    AuditLogRow,
    AuditOutcome,
    PruneOptions,
    PruneResult,
    RequestContext,
} from "./audit.js";
export type {
    ApiKeyRow,
    Page,
    PageOptions,
    PrincipalBindingRow,
    ReadApi,
    RoleRow,
    RoleScopeRow,
    ScopeRow,
    TenantBindingRow,
    TenantRow,
} from "./reads.js";
export {
    AUTHZ_FUNCTIONS,
    fromQuery,
    fromSupabase,
    type AuthzFunction,
    type AuthzTransport,
    type RpcArgs,
    type SupabaseRpcClient,
    type SupabaseRpcError,
} from "./transport.js";
export { isUuid } from "./uuid.js";
export {
    AuthKitError,
    AuthzConfigError,
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

/**
 * Exactly one of `supabase`, `query` or `transport` says how to reach the database, and
 * `createAuthKit` throws on zero or several. They are optional fields on one interface, rather
 * than a union, so the framework bindings can keep extending it.
 */
export interface AuthKitOptions {
    /**
     * A server-side supabase-js client holding the project's **secret key**. Needs the `authz`
     * schema exposed to PostgREST. See `fromSupabase`.
     */
    supabase?: SupabaseRpcClient;
    /**
     * Runs parameterized SQL on a direct Postgres connection as the owner, e.g.
     * `(sql, params) => pool.query(sql, [...params]).then(r => r.rows)`. See `fromQuery`.
     */
    query?: QueryFn;
    /** Any other transport. Both of the above are shorthands for one of these. */
    transport?: AuthzTransport;
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
    /** Audit logging. Successful writes log themselves in SQL regardless of what is set here. */
    audit?: AuditOptions;
}

export interface AuditOptions {
    /**
     * Whether a refusal records a denied row -- both a write the SQL guards refused and a
     * request a scope guard turned away. Default true.
     *
     * This is the only part of audit logging that is optional, because it is the only part
     * that costs a round trip on a path that would otherwise make none, and the only part that
     * a caller can drive: a public endpoint behind a scope guard writes one row per probe.
     * Successful writes log inside the transaction they are already in and cannot be turned off.
     */
    denials?: boolean | undefined;
    /**
     * Called when writing an audit row itself fails. Audit writes never reject -- a logging
     * failure must not become the caller's problem, least of all on a path that is already
     * reporting a denial -- so this is the only way to find out that one did.
     */
    onError?: ((error: unknown) => void) | undefined;
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
     * The read and write APIs with this actor pre-bound. Take it once per request, from the
     * resolved principal, so the wrong actor cannot be threaded into a call by hand.
     *
     * `requestContext` is bound the same way and for the same reason: every audit row the
     * writes produce carries the request that caused it, without any call site remembering to
     * pass it.
     */
    as(
        actorPrincipalId: string,
        requestContext?: RequestContext | null,
    ): ActorApi;
    /**
     * Appends an audit row as any actor, including none. Resolves to the row's id, or null if
     * the write failed -- it never rejects.
     *
     * `kit.as(actor).logAudit` is the form to prefer; this one exists for what has no actor to
     * bind, which in practice means a request that presented a credential resolving to no
     * principal.
     */
    logAudit(entry: AuditEntry): Promise<string | null>;
    /**
     * Records a refusal, unless `audit.denials` is off. The guard calls this; so does anything
     * else that decides a caller may not do something.
     */
    logDenial(entry: Omit<AuditEntry, "outcome">): Promise<void>;
    /**
     * Deletes one batch of audit rows older than `before`.
     *
     * **On the kit rather than on `as(actor)`, because no principal does this.** Retention is a
     * maintenance job: a cron worker has no principal to name, and the SQL function takes no
     * actor and checks no scope -- authority is the connection, as it is for the other operator
     * tools. Reaching it therefore means holding the owner connection or the secret key.
     *
     * Safe to run on every replica of a service. An advisory lock single-flights it, and a
     * caller that does not get the lock comes back with `lock_acquired: false` having examined
     * nothing -- which is not the same as having found nothing to delete, and a loop must treat
     * the two differently.
     */
    pruneAuditLogs(options: PruneOptions): Promise<PruneResult>;
}

/** Everything that acts as a principal: the writes, and the reads that answer as that principal. */
export type ActorApi = WriteApi & ReadApi;

/**
 * Every failure a transport raises passes through here once, so reads, writes and checks all
 * surface the same typed errors whichever transport is underneath.
 */
function typed(transport: AuthzTransport): AuthzTransport {
    return {
        scalar: (fn, args) =>
            transport.scalar(fn, args).catch(rethrowAsAuthKitError),
        rows: (fn, args) => transport.rows(fn, args).catch(rethrowAsAuthKitError),
    };
}

function transportFrom(options: AuthKitOptions): AuthzTransport {
    const given = [
        options.supabase === undefined ? undefined : fromSupabase(options.supabase),
        options.query === undefined ? undefined : fromQuery(options.query),
        options.transport,
    ].filter((transport): transport is AuthzTransport => transport !== undefined);

    if (given.length !== 1) {
        throw new TypeError(
            "createAuthKit requires exactly one of `supabase`, `query` or `transport`",
        );
    }

    return typed(given[0] as AuthzTransport);
}

export function createAuthKit(options: AuthKitOptions): AuthKit {
    const transport = transportFrom(options);

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

    const auditDenials = options.audit?.denials ?? true;
    const onAuditError = options.audit?.onError;

    return {
        verifyBearer,

        principalForAuthUser: authUserId =>
            principalForAuthUser(transport, authUserId),

        principalForApiKey: key => principalForApiKey(transport, key),

        principalIsActive: principalId =>
            principalIsActive(transport, principalId),

        async resolvePrincipal({ bearer, apiKey }) {
            // An API key wins when both are sent, so verify_api_key runs at most once and a
            // request never pays for two identity round trips.
            if (apiKey) {
                const principalId = await principalForApiKey(transport, apiKey);

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
                        : await principalForAuthUser(transport, authUserId);

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
            hasScope(transport, principalId, tenantId, scope),

        effectiveScopes: (principalId, tenantId) =>
            effectiveScopes(transport, principalId, tenantId),

        as: (actorPrincipalId, requestContext = null) => ({
            ...createWriteApi(transport, actorPrincipalId, {
                requestContext,
                auditDenials,
                onAuditError,
            }),
            ...createReadApi(transport, actorPrincipalId),
        }),

        logAudit: entry => logAudit(transport, entry, onAuditError),

        async logDenial(entry) {
            if (!auditDenials) {
                return;
            }

            await logAudit(transport, { ...entry, outcome: "denied" }, onAuditError);
        },

        pruneAuditLogs: options => pruneAuditLogs(transport, options),
    };
}
