import { AuthKitError, AuthzDeniedError } from "./errors.js";

/**
 * An authorization outcome with an HTTP status attached.
 *
 * Shared by every framework binding. `status` is also the property Fastify's default error
 * handler and Express's `finalhandler` read, so a guard error renders with the right status even
 * where no error handler of ours is installed.
 */
export class HttpAuthzError extends Error {
    readonly status: number;
    readonly code: string;

    constructor(status: number, code: string, message: string) {
        super(message);
        this.name = new.target.name;
        this.status = status;
        this.code = code;
    }
}

/** No credential was presented at all. */
export class UnauthenticatedError extends HttpAuthzError {
    constructor() {
        super(401, "unauthenticated", "no credential presented");
    }
}

/**
 * A credential was presented and the caller holds no authority.
 *
 * Covers two distinct situations on purpose. One is an ordinary missing scope. The other is the
 * state the model doc raises as open question 1: a token that verified against the project's own
 * JWKS but maps to no authz identity, because the address it belongs to is held by a retired
 * identity. That caller is authenticated with zero authority -- a 403, never a 500.
 */
export class ForbiddenError extends HttpAuthzError {
    readonly scope: string | undefined;

    constructor(message: string, scope?: string) {
        super(403, "forbidden", message);
        this.scope = scope;
    }
}

/**
 * The tenant hook produced nothing usable. A 400, because a request that does not say which
 * tenant it concerns cannot be authorized -- and must never be allowed on that basis.
 */
export class TenantRequiredError extends HttpAuthzError {
    constructor(message = "could not resolve a tenant for this request") {
        super(400, "tenant_required", message);
    }
}

/**
 * A guard ran on a route whose authentication step never ran. A wiring bug, and deliberately a
 * 500: the alternative is inferring intent from a missing context, and every safe inference
 * there is indistinguishable from letting the request through.
 *
 * The message is a parameter because the fix is framework-specific -- mounting a middleware in
 * Express, registering a plugin in Fastify.
 */
export class MiddlewareNotInstalledError extends HttpAuthzError {
    constructor(
        message = "authKit context missing: the authentication step did not run for this route",
    ) {
        super(500, "middleware_missing", message);
    }
}

/** Maps anything thrown by a binding or the core to a status and code. */
export function statusOf(error: unknown): { status: number; code: string } | null {
    if (error instanceof HttpAuthzError) {
        return { status: error.status, code: error.code };
    }

    // A guard in SQL refused. From a caller's side that is the same answer as a missing scope.
    if (error instanceof AuthzDeniedError) {
        return { status: 403, code: "forbidden" };
    }

    if (error instanceof AuthKitError) {
        return { status: 500, code: "authz_error" };
    }

    return null;
}
