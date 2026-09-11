const UUID =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Guards every value that becomes a uuid parameter.
 *
 * Not hygiene: Postgres answers a malformed uuid with `22P02 invalid input syntax`, which
 * surfaces as a 500. A typo'd route parameter or a client-supplied garbage tenant must be a 400,
 * and a bad `sub` claim must be a 401 -- neither is a server fault, and neither should reach the
 * database to find out.
 */
export function isUuid(value: unknown): value is string {
    return typeof value === "string" && UUID.test(value);
}
