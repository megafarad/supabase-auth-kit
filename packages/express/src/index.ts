import {
    MiddlewareNotInstalledError,
    checkAllScopes,
    checkAnyScope,
    checkScope,
    createAuthKit,
    createAuthzContext,
    credentialsFromHeaders,
    enforceGuard,
    enforceIdentity,
    statusOf,
    type AuthKit,
    type AuthKitOptions,
    type AuthzContext,
    type GuardCheck,
    type RequestContext,
    type TenantResolver as CoreTenantResolver,
} from "@sirhc77/supabase-auth-kit-core";
import { randomUUID } from "node:crypto";

import type { ErrorRequestHandler, Request, RequestHandler } from "express";

import { wrapAsync } from "./async.js";

// The errors, the context shape and the tenant helpers are shared with every binding, so they
// live in the core and are re-exported here unchanged.
export {
    ForbiddenError,
    HttpAuthzError,
    MiddlewareNotInstalledError,
    TenantRequiredError,
    UnauthenticatedError,
    statusOf,
    tenantFromBody,
    tenantFromHeader,
    tenantFromParam,
    tenantFromQuery,
} from "@sirhc77/supabase-auth-kit-core";
export type {
    AuditEntry,
    AuditFilter,
    AuditLogRow,
    AuthKit,
    AuthzContext,
    RequestContext,
} from "@sirhc77/supabase-auth-kit-core";

/**
 * Where a request says which tenant it concerns. The core's helpers (`tenantFromParam` and
 * friends) are typed over a structural request and slot straight in.
 *
 * Returning nothing is a 400, never an allow.
 */
export type TenantResolver = CoreTenantResolver<Request>;

declare global {
    // eslint-disable-next-line @typescript-eslint/no-namespace
    namespace Express {
        interface Request {
            /**
             * Optional on purpose: a route not mounted behind `authenticate()` genuinely has no
             * context, and pretending otherwise is how a fall-open gets written. Read it with
             * `getAuthContext(req)`, which throws instead of yielding undefined.
             *
             * Named `authKit` rather than `auth` to avoid a hard compile error for consumers who
             * also use express-jwt or express-oauth2-jwt-bearer, both of which merge `req.auth`.
             */
            authKit?: AuthzContext;
        }
    }
}

export interface ExpressAuthKitOptions extends AuthKitOptions {
    /** Where the tenant comes from. Required: every check is per (principal, tenant, scope). */
    resolveTenant: TenantResolver;
    /** Header carrying a plaintext API key. Defaults to `x-api-key`. */
    apiKeyHeader?: string;
    /**
     * What the audit rows written during a request should say about it. Defaults to
     * `requestContextFromExpress`; return null to record nothing about the request itself.
     */
    requestContext?: (request: Request) => RequestContext | null;
}

/**
 * The default request context on Express, which is poorer than Fastify's in two ways worth
 * knowing about.
 *
 * **The route is the URL, not the pattern.** `req.route` is not populated until Express has
 * matched a route, and `authenticate()` runs before that, so `/tenants/9f3.../members` is what
 * lands in the column rather than `/tenants/:id/members`. Grouping audit rows by route therefore
 * needs the pattern supplied here by a consumer who has it.
 *
 * **The request id is generated unless a header carries one.** Express has no equivalent of
 * Fastify's `request.id`, so `x-request-id` is honoured if present and a uuid minted otherwise.
 * A minted id still correlates the rows of one request with each other, which is most of the
 * value; correlating them with the app's own logs needs the app to use the same id.
 *
 * `req.ip` honours the app's `trust proxy` setting, so a deployment behind a load balancer that
 * has not set it will record the balancer's address.
 */
export function requestContextFromExpress(request: Request): RequestContext {
    const header = request.headers["x-request-id"];

    return {
        requestId: (Array.isArray(header) ? header[0] : header) ?? randomUUID(),
        method: request.method,
        route: request.originalUrl || request.url,
        ip: request.ip,
        userAgent: request.headers["user-agent"],
    };
}

export interface GuardOptions {
    /** Overrides the factory-level tenant hook for one route. */
    resolveTenant?: TenantResolver;
}

/**
 * Reads the context, throwing if `authenticate()` was never mounted.
 *
 * Guards use this rather than optional chaining, because the shape to make unwritable is
 *
 *   if (req.authKit && !(await req.authKit.has(t, s))) deny();
 *
 * which silently allows the request when the middleware is missing.
 */
export function getAuthContext(req: Request): AuthzContext {
    const context = req.authKit;

    if (context === undefined) {
        throw new MiddlewareNotInstalledError(
            "authKit context missing: mount authenticate() before requireScope()",
        );
    }

    return context;
}

export interface ExpressAuthKit {
    readonly kit: AuthKit;
    /**
     * Resolves the request's credentials and attaches the context. **Never rejects a request** --
     * a missing or bad credential yields a context with no principal, and the guard decides.
     * That is safe only because an absent principal carries zero scopes and the guard is the
     * enforcement point; it is what makes 401 and 403 distinguishable further down.
     */
    authenticate(): RequestHandler;
    /**
     * Requires somebody, not a scope: 401 without a credential, 403 for one that maps to no
     * authz identity, and no database round trip either way.
     *
     * For the routes whose authority the request cannot name -- `createWorkspace`, which needs
     * no scope at any tenant, and the writes anchored on a row's own tenant (`revokeBinding`,
     * `updateRole`, `addRoleScope`, `removeRoleScope`, `revokeApiKey`) -- where SQL is the only
     * place the anchor is readable. See `enforceIdentity` in the core for why a `requireScope`
     * on some other tenant is worse than none.
     *
     * **Not a cheaper `requireScope`, and never on a read**: reads refuse by filtering, so this
     * would answer `200 []` where `requireScope` answers 403.
     */
    requireIdentity(): RequestHandler;
    requireScope(scope: string, options?: GuardOptions): RequestHandler;
    /** One `effective_scopes` round trip regardless of how many scopes are listed. */
    requireAllScopes(scopes: readonly string[], options?: GuardOptions): RequestHandler;
    requireAnyScope(scopes: readonly string[], options?: GuardOptions): RequestHandler;
    /** Opt-in error middleware mapping this package's errors to a JSON response. */
    errorHandler(): ErrorRequestHandler;
}

export function createExpressAuthKit(
    options: ExpressAuthKitOptions,
): ExpressAuthKit {
    const {
        resolveTenant,
        apiKeyHeader = "x-api-key",
        requestContext = requestContextFromExpress,
        ...kitOptions
    } = options;
    const kit = createAuthKit(kitOptions);

    /** The decision order lives in the core's `enforceGuard`; this only binds it to Express. */
    function guard(check: GuardCheck, options: GuardOptions | undefined): RequestHandler {
        const resolver = options?.resolveTenant ?? resolveTenant;

        return wrapAsync(async (req, _res, next) => {
            await enforceGuard(getAuthContext(req), () => resolver(req), check);

            next();
        });
    }

    return {
        kit,

        authenticate: () =>
            wrapAsync(async (req, _res, next) => {
                const resolved = await kit.resolvePrincipal(
                    credentialsFromHeaders(req.headers, apiKeyHeader),
                );

                req.authKit = createAuthzContext(
                    kit,
                    resolved,
                    requestContext(req),
                );

                next();
            }),

        requireIdentity: () =>
            wrapAsync(async (req, _res, next) => {
                await enforceIdentity(getAuthContext(req));

                next();
            }),

        requireScope: (scope, options) => guard(checkScope(scope), options),

        requireAllScopes: (required, options) =>
            guard(checkAllScopes(required), options),

        requireAnyScope: (accepted, options) =>
            guard(checkAnyScope(accepted), options),

        errorHandler:
            (): ErrorRequestHandler =>
            (error, _req, res, next) => {
                const mapped = statusOf(error);

                // Anything that is not ours belongs to the consumer's handler untouched.
                if (mapped === null) {
                    next(error);

                    return;
                }

                res.status(mapped.status).json({
                    error: mapped.code,
                    message: (error as Error).message,
                });
            },
    };
}
