import {
    MiddlewareNotInstalledError,
    checkAllScopes,
    checkAnyScope,
    checkScope,
    createAuthKit,
    createAuthzContext,
    credentialsFromHeaders,
    enforceGuard,
    statusOf,
    type AuthKit,
    type AuthKitOptions,
    type AuthzContext,
    type GuardCheck,
    type TenantResolver as CoreTenantResolver,
} from "@sirhc77/supabase-auth-kit-core";
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
export type { AuthKit, AuthzContext } from "@sirhc77/supabase-auth-kit-core";

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
    const { resolveTenant, apiKeyHeader = "x-api-key", ...kitOptions } = options;
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

                req.authKit = createAuthzContext(kit, resolved);

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
