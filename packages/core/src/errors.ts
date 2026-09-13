/**
 * Typed errors over the SQL layer's failures.
 *
 * The write functions signal refusal with `raise exception`, which arrives as SQLSTATE P0001
 * for every guard alike -- a lacked scope, an invisible role and a retired identity are
 * indistinguishable by code. All of them are mapped to `AuthzDeniedError`, which is the honest
 * reading from a caller's point of view and has the useful side effect of not leaking whether
 * a role or tenant exists.
 *
 * Some states do come back distinctly and are worth separating:
 *   P0002 / P0003  a `select ... into strict` found no row or too many -- the database is not in
 *                  the shape the function expects, typically the bootstrap migration not having
 *                  run. An operator problem, not a caller problem.
 *   23505          unique violation, e.g. a second parentless tenant.
 *   23503 / 23514  foreign key or check violation -- a bad id or an impossible combination.
 *   22P02          a value that does not cast, e.g. a malformed page cursor.
 *   42501          permission denied: the connection's role cannot execute the function.
 *   PGRST106/202   PostgREST's own codes for an unexposed schema and an unknown function.
 *
 * The last three are wiring, not refusals, and are deliberately NOT AuthzDeniedError: that
 * maps to a 403, and a misconfigured deployment answering 403 to everyone reads as a caller
 * problem when it is an operator one.
 *
 * Finer classification of the P0001 group would need `using errcode = ...` added to those 34
 * raise sites in `001_auth_kit_functions.sql`. Adding it later only changes the table below.
 */
export class AuthKitError extends Error {
    readonly sqlState: string | undefined;

    constructor(message: string, sqlState?: string, options?: { cause?: unknown }) {
        super(message, options);
        this.name = new.target.name;
        this.sqlState = sqlState;
    }
}

/** A guard refused the operation. The caller lacks the authority, or the target is not theirs. */
export class AuthzDeniedError extends AuthKitError {}

/** The schema is not in the expected state -- usually the bootstrap migration has not run. */
export class AuthzStateError extends AuthKitError {}

/** The write collided with an existing row. */
export class AuthzConflictError extends AuthKitError {}

/** A bad identifier, a malformed cursor, or an impossible combination of arguments. */
export class AuthzUsageError extends AuthKitError {}

/**
 * The kit is wired up wrongly: the connection cannot reach the `authz` functions at all. Never
 * a caller problem, and never something to retry.
 */
export class AuthzConfigError extends AuthKitError {}

const BY_SQLSTATE: Readonly<Record<string, typeof AuthKitError>> = {
    P0001: AuthzDeniedError,
    P0002: AuthzStateError,
    P0003: AuthzStateError,
    "23505": AuthzConflictError,
    "23503": AuthzUsageError,
    "23514": AuthzUsageError,
    "22P02": AuthzUsageError,
    "42501": AuthzConfigError,
    PGRST106: AuthzConfigError,
    PGRST202: AuthzConfigError,
};

/** What to do about each wiring failure, appended to the database's own message. */
const FIX: Readonly<Record<string, string>> = {
    "42501":
        "the connection's role may not execute this authz function. Use the owner connection, or a supabase-js client holding the secret key -- never a publishable or anon key, or a client with a user signed in",
    PGRST106:
        "the authz schema is not exposed to PostgREST. Add it to [api] schemas in supabase/config.toml, or to the exposed schemas in the dashboard's API settings",
    PGRST202:
        "PostgREST cannot see this authz function. Apply the kit's migrations, then reload the schema cache with NOTIFY pgrst, 'reload schema'",
};

/**
 * Duck-typed rather than driver-specific: `pg` and `postgres.js` both expose `code`, and the
 * supabase-js transport re-raises PostgREST's errors in the same shape. This package depends on
 * none of them.
 */
function sqlStateOf(error: unknown): string | undefined {
    const code = (error as { code?: unknown } | null | undefined)?.code;

    return typeof code === "string" ? code : undefined;
}

/**
 * Re-throws a database failure as a typed error, preserving the original as `cause`. Anything
 * unrecognised is rethrown untouched -- a connection reset is not an authorization outcome and
 * must not be dressed up as one.
 */
export function rethrowAsAuthKitError(error: unknown): never {
    const sqlState = sqlStateOf(error);
    const Ctor = sqlState === undefined ? undefined : BY_SQLSTATE[sqlState];

    if (Ctor === undefined || sqlState === undefined) {
        throw error;
    }

    const original = String(
        (error as { message?: unknown } | null)?.message ?? "authz call failed",
    );
    const fix = FIX[sqlState];

    throw new Ctor(fix === undefined ? original : `${original}: ${fix}`, sqlState, {
        cause: error,
    });
}
