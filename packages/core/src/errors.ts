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

/** A bad identifier or an impossible combination of arguments. */
export class AuthzUsageError extends AuthKitError {}

const BY_SQLSTATE: Readonly<Record<string, typeof AuthKitError>> = {
    P0001: AuthzDeniedError,
    P0002: AuthzStateError,
    P0003: AuthzStateError,
    "23505": AuthzConflictError,
    "23503": AuthzUsageError,
    "23514": AuthzUsageError,
};

/**
 * Duck-typed rather than driver-specific: `pg` and `postgres.js` both expose `code`, and this
 * package depends on neither.
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

    if (Ctor === undefined) {
        throw error;
    }

    const message =
        (error as { message?: unknown } | null)?.message ?? "authz call failed";

    throw new Ctor(String(message), sqlState, { cause: error });
}
