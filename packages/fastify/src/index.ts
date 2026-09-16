import { STATUS_CODES } from "node:http";

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
    type RequestContext,
    type TenantResolver as CoreTenantResolver,
} from "@sirhc77/supabase-auth-kit-core";
import type {
    FastifyPluginAsync,
    FastifyReply,
    FastifyRequest,
} from "fastify";
import fp from "fastify-plugin";

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
export type TenantResolver = CoreTenantResolver<FastifyRequest>;

declare module "fastify" {
    interface FastifyRequest {
        /**
         * Null until the plugin's `onRequest` hook has run, and absent entirely on a route the
         * plugin does not cover. Read it with `getAuthContext(request)`, which throws in both
         * cases instead of yielding a value a guard could mistake for "no check needed".
         *
         * Declared here rather than in a side `.d.ts`, so import elision cannot drop it.
         */
        authKit: AuthzContext | null;
    }
}

/**
 * A guard, usable as any route-level request hook -- `onRequest`, `preValidation` or
 * `preHandler`. Denial is a rejection, which Fastify routes to the error handler.
 */
export type AuthzHook = (request: FastifyRequest, reply: FastifyReply) => Promise<void>;

export interface FastifyAuthKitOptions extends AuthKitOptions {
    /** Where the tenant comes from. Required: every check is per (principal, tenant, scope). */
    resolveTenant: TenantResolver;
    /** Header carrying a plaintext API key. Defaults to `x-api-key`. */
    apiKeyHeader?: string;
    /**
     * What the audit rows written during a request should say about it. Defaults to
     * `requestContextFromFastify`; return null to record nothing about the request itself.
     */
    requestContext?: (request: FastifyRequest) => RequestContext | null;
}

/**
 * The default request context on Fastify, which can be exact where Express cannot.
 *
 * `request.id` is Fastify's own, so it is the id already in its logs -- honouring
 * `requestIdHeader` when the caller sent one -- and nothing has to be generated. `routeOptions.url`
 * is the matched **pattern** (`/tenants/:id/members`), so audit rows group by route rather than
 * by every distinct path; it is undefined for a request that matched no route, where the raw URL
 * is the honest answer.
 *
 * `request.ip` honours `trustProxy`, so a deployment behind a load balancer that has not set it
 * will record the balancer's address.
 */
export function requestContextFromFastify(request: FastifyRequest): RequestContext {
    return {
        requestId: request.id,
        method: request.method,
        route: request.routeOptions?.url ?? request.url,
        ip: request.ip,
        userAgent: request.headers["user-agent"],
    };
}

export interface GuardOptions {
    /** Overrides the factory-level tenant hook for one route. */
    resolveTenant?: TenantResolver;
}

/**
 * Reads the context, throwing if the plugin's hook never ran for this request.
 *
 * Guards use this rather than optional chaining, because the shape to make unwritable is
 *
 *   if (request.authKit && !(await request.authKit.has(t, s))) deny();
 *
 * which silently allows the request when the plugin is missing.
 */
export function getAuthContext(request: FastifyRequest): AuthzContext {
    // Undefined when the decorator is absent from this context, null when it exists but the
    // hook did not run. Both are the same wiring bug.
    const context = (request as { authKit?: AuthzContext | null }).authKit;

    if (context === undefined || context === null) {
        throw new MiddlewareNotInstalledError(
            "authKit context missing: register auth.plugin before routes using requireScope()",
        );
    }

    return context;
}

export interface FastifyAuthKit {
    readonly kit: AuthKit;
    /**
     * Decorates the request and adds an `onRequest` hook that resolves its credentials. Wrapped
     * in `fastify-plugin`, so it covers the context it is registered in rather than only its own.
     *
     * **Never rejects a request** -- a missing or bad credential yields a context with no
     * principal, and the guard decides. That is safe only because an absent principal carries
     * zero scopes and the guard is the enforcement point; it is what makes 401 and 403
     * distinguishable further down, and lets a public route sit in the same context.
     */
    readonly plugin: FastifyPluginAsync;
    requireScope(scope: string, options?: GuardOptions): AuthzHook;
    /** One `effective_scopes` round trip regardless of how many scopes are listed. */
    requireAllScopes(scopes: readonly string[], options?: GuardOptions): AuthzHook;
    requireAnyScope(scopes: readonly string[], options?: GuardOptions): AuthzHook;
    /**
     * Opt-in, for `app.setErrorHandler`. Guard errors already render correctly without it --
     * they carry `status` and `code`, which Fastify's default handler honours. What this adds is
     * the core's write-API errors: `AuthzDeniedError` becomes a 403 instead of a 500. Anything
     * that is not ours is rethrown, which Fastify hands to the parent error handler untouched.
     */
    errorHandler(error: Error, request: FastifyRequest, reply: FastifyReply): void;
}

export function createFastifyAuthKit(
    options: FastifyAuthKitOptions,
): FastifyAuthKit {
    const {
        resolveTenant,
        apiKeyHeader = "x-api-key",
        requestContext = requestContextFromFastify,
        ...kitOptions
    } = options;
    const kit = createAuthKit(kitOptions);

    /** The decision order lives in the core's `enforceGuard`; this only binds it to Fastify. */
    function guard(check: GuardCheck, options: GuardOptions | undefined): AuthzHook {
        const resolver = options?.resolveTenant ?? resolveTenant;

        return async request => {
            await enforceGuard(getAuthContext(request), () => resolver(request), check);
        };
    }

    // Built per factory call: fastify-plugin stamps symbols onto the function it wraps.
    const plugin: FastifyPluginAsync = async fastify => {
        // Fastify 5 accepts only null or a getter for a reference-type request decorator.
        fastify.decorateRequest("authKit", null);

        // onRequest, and at the instance level: instance hooks run before route hooks of the
        // same stage, so a guard sees the context whichever stage it is mounted at.
        fastify.addHook("onRequest", async request => {
            const resolved = await kit.resolvePrincipal(
                credentialsFromHeaders(request.headers, apiKeyHeader),
            );

            request.authKit = createAuthzContext(
                kit,
                resolved,
                requestContext(request),
            );
        });
    };

    return {
        kit,

        plugin: fp(plugin, {
            name: "@sirhc77/supabase-auth-kit-fastify",
            fastify: "5.x",
        }),

        requireScope: (scope, options) => guard(checkScope(scope), options),

        requireAllScopes: (required, options) =>
            guard(checkAllScopes(required), options),

        requireAnyScope: (accepted, options) =>
            guard(checkAnyScope(accepted), options),

        errorHandler(error, request, reply) {
            const mapped = statusOf(error);

            // Rethrowing, not replying: Fastify passes a throw from an error handler to the
            // parent context's handler, so the consumer's own handling still sees the error.
            if (mapped === null) {
                throw error;
            }

            // An operator problem -- typically the bootstrap migration not having run -- must
            // not vanish into a response body.
            if (mapped.status >= 500) {
                request.log.error({ err: error }, "authz error");
            }

            // The same shape Fastify's default handler gives a guard error, so a response does
            // not change shape depending on whether this handler is installed.
            void reply.code(mapped.status).send({
                statusCode: mapped.status,
                code: mapped.code,
                error: STATUS_CODES[mapped.status] ?? "Error",
                message: error.message,
            });
        },
    };
}
