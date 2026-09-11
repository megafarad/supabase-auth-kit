import type { HeaderBag } from "./headers.js";
import { isUuid } from "./uuid.js";

/**
 * The parts of a request the tenant helpers read. Structural, so the core imports no framework:
 * Express's `Request` and Fastify's `FastifyRequest` both satisfy it, and a resolver taking a
 * `TenantSource` is therefore assignable to either binding's resolver type.
 */
export interface TenantSource {
    readonly params?: unknown;
    readonly query?: unknown;
    readonly body?: unknown;
    readonly headers: HeaderBag;
}

/**
 * Where a request says which tenant it concerns. Inherently app-specific -- a route param, a
 * subdomain, a header, a body field -- so it is a hook rather than a convention. Each binding
 * narrows `R` to its own request type.
 *
 * Returning nothing is a 400, never an allow.
 */
export type TenantResolver<R = TenantSource> = (
    req: R,
) => string | null | undefined | Promise<string | null | undefined>;

/**
 * Every helper validates uuid shape and returns undefined when absent or malformed.
 *
 * That is not cosmetic. An arbitrary string reaching `authz.has_scope` makes Postgres raise
 * `22P02 invalid input syntax for type uuid`, which surfaces as a 500 -- so a typo'd param name
 * or a client-supplied garbage tenant would look like a server fault instead of a bad request.
 *
 * Letting the client name the tenant is safe here: `has_scope` is the check, and a tenant the
 * caller holds nothing at answers false identically to one that does not exist, so there is no
 * enumeration oracle. The consumer's obligation is ordering -- guard first, then handler. Never
 * use a resolved tenant id to scope a query before the guard has run.
 */
export function tenantFromParam(name: string): TenantResolver {
    return req => {
        const value = (req.params as Record<string, unknown> | undefined)?.[name];

        return isUuid(value) ? value : undefined;
    };
}

export function tenantFromHeader(name: string): TenantResolver {
    return req => {
        const value = req.headers[name.toLowerCase()];

        // Never join an array-valued header: two values means an ambiguous request.
        return isUuid(value) ? value : undefined;
    };
}

export function tenantFromQuery(name: string): TenantResolver {
    return req => {
        const value = (req.query as Record<string, unknown> | undefined)?.[name];

        return isUuid(value) ? value : undefined;
    };
}

/**
 * Requires the body to have been parsed before the guard runs; a missing body is simply an
 * unresolved tenant, so running too early fails closed as a 400.
 */
export function tenantFromBody(name: string): TenantResolver {
    return req => {
        const value = (req.body as Record<string, unknown> | null | undefined)?.[name];

        return isUuid(value) ? value : undefined;
    };
}
