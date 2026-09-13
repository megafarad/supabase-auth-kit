import type { QueryFn, Row } from "./query.js";

/**
 * Every `authz` function this package calls, and nothing else.
 *
 * It is the same list `20260913040000_auth_kit_rpc_privileges.sql` grants to `service_role`,
 * and an integration test holds the two equal -- which is why it is a value and not only a
 * type. Anything missing from the grant fails as a permission error on the supabase-js
 * transport; anything missing from here cannot be called.
 */
export const AUTHZ_FUNCTIONS = [
    // identity
    "principal_for_auth_user",
    "verify_api_key",
    "principal_is_active",
    // authorization
    "has_scope",
    "effective_scopes",
    // writes
    "grant_role",
    "invite_user",
    "revoke_binding",
    "create_role",
    "update_role",
    "add_role_scope",
    "remove_role_scope",
    "create_scope",
    "create_tenant",
    "create_workspace",
    "update_tenant",
    "create_api_key",
    "revoke_api_key",
    // reads
    "get_tenant",
    "list_child_tenants",
    "list_principal_bindings",
    "list_tenant_bindings",
    "list_roles",
    "list_role_scopes",
    "list_scopes",
    "list_api_keys",
] as const;

export type AuthzFunction = (typeof AUTHZ_FUNCTIONS)[number];

/**
 * Arguments keyed by the SQL parameter names, `p_` prefix and all. Both transports pass them by
 * name -- PostgREST has no other way, and Postgres accepts `fn(p_x => $1)` -- so the names are
 * the contract and argument order never matters. An `undefined` value is omitted, which lets
 * the function's own default apply; `null` is passed as SQL null.
 */
export type RpcArgs = Readonly<Record<string, unknown>>;

/**
 * How core reaches the database: by function name, never by SQL text.
 *
 * Two implementations ship -- `fromQuery` over any Postgres driver, and `fromSupabase` over a
 * supabase-js client -- and they must be indistinguishable to everything above them. That
 * includes value shapes: timestamps arrive as ISO-8601 strings from both, since that is all
 * JSON can carry.
 */
export interface AuthzTransport {
    /** Calls a function returning a single value. Null for a SQL null or a `void` function. */
    scalar(fn: AuthzFunction, args: RpcArgs): Promise<unknown>;
    /** Calls a set-returning function. */
    rows(fn: AuthzFunction, args: RpcArgs): Promise<Row[]>;
}

/**
 * Names are interpolated into SQL text by `fromQuery`, so they are checked even though the
 * types already restrict them: types are erased, and a transport is public API. Nothing a
 * request supplies ever becomes a name -- values only ever travel as bind parameters.
 */
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

function assertIdentifier(name: string): void {
    if (!IDENTIFIER.test(name)) {
        throw new TypeError(`not a valid authz identifier: ${JSON.stringify(name)}`);
    }
}

function definedArgs(args: RpcArgs): [string, unknown][] {
    return Object.entries(args).filter(([, value]) => value !== undefined);
}

function normalizeValue(value: unknown): unknown {
    return value instanceof Date ? value.toISOString() : value;
}

function normalizeRow(row: Row): Row {
    return Object.fromEntries(
        Object.entries(row).map(([key, value]) => [key, normalizeValue(value)]),
    );
}

/**
 * The transport over a Postgres driver: `pg`, `postgres.js`, or anything else that runs a
 * parameterized statement and returns rows.
 *
 * The connection has to be one that can execute the functions: the owner (`postgres`), or a
 * role granted what `service_role` is granted. It bypasses nothing the functions do not
 * already enforce, since every statement is a single call to one of them.
 */
export function fromQuery(query: QueryFn): AuthzTransport {
    function call(fn: AuthzFunction, args: RpcArgs): { sql: string; params: unknown[] } {
        assertIdentifier(fn);

        const params: unknown[] = [];

        const named = definedArgs(args).map(([name, value]) => {
            assertIdentifier(name);
            params.push(value);

            return `${name} => $${params.length}`;
        });

        return { sql: `authz.${fn}(${named.join(", ")})`, params };
    }

    return {
        async scalar(fn, args) {
            const { sql, params } = call(fn, args);
            // Aliased, so extraction never depends on how a driver names an unnamed column.
            const rows = await query(`select ${sql} as result`, params);
            const value = rows[0]?.["result"];

            return value === undefined ? null : normalizeValue(value);
        },

        async rows(fn, args) {
            const { sql, params } = call(fn, args);
            const rows = await query(`select * from ${sql}`, params);

            return rows.map(normalizeRow);
        },
    };
}

/** The error half of a supabase-js response. */
export interface SupabaseRpcError {
    message: string;
    code?: string | undefined;
    details?: string | null | undefined;
    hint?: string | null | undefined;
}

/**
 * A supabase-js client, typed structurally so core does not depend on `@supabase/supabase-js`.
 *
 * Deliberately loose. A client created with generated database types narrows `schema()` to the
 * schemas in those types, which normally do not include `authz`, and any precise signature here
 * would reject it -- forcing every typed app to cast. The precise shape core relies on is
 * `SupabaseRpcShape`, and `fromSupabase` is the only place that assumes it.
 */
export interface SupabaseRpcClient {
    schema(schema: never): unknown;
}

/** What `fromSupabase` actually calls on the client. */
interface SupabaseRpcShape {
    schema(schema: "authz"): {
        rpc(
            fn: string,
            args?: Record<string, unknown>,
        ): PromiseLike<{ data: unknown; error: SupabaseRpcError | null }>;
    };
}

/**
 * The transport over supabase-js. The client must hold a **secret key** (`sb_secret_...`, or
 * the legacy `service_role` JWT) and must never leave the server: it can act as any principal.
 *
 * Create it with `auth: { persistSession: false, autoRefreshToken: false }`. A client that has
 * signed a user in sends that user's token instead of the key, which makes PostgREST switch to
 * `authenticated` -- a role with no access to `authz`, so every call fails with a permission
 * error. That fails closed, but it is a confusing way to find out.
 *
 * The project has to expose the `authz` schema to PostgREST: add it to `[api] schemas` in
 * `supabase/config.toml` locally, or to the exposed schemas in the dashboard's API settings.
 */
export function fromSupabase(client: SupabaseRpcClient): AuthzTransport {
    async function call(fn: AuthzFunction, args: RpcArgs): Promise<unknown> {
        assertIdentifier(fn);

        const { data, error } = await (client as unknown as SupabaseRpcShape)
            .schema("authz")
            .rpc(fn, Object.fromEntries(definedArgs(args)));

        if (error !== null) {
            // supabase-js resolves rather than rejects. Re-raise it carrying the SQLSTATE (or
            // PostgREST's own PGRST code) as `code`, the same shape pg and postgres.js throw,
            // so error classification does not care which transport produced it.
            throw Object.assign(new Error(error.message), {
                code: error.code,
                details: error.details ?? null,
                hint: error.hint ?? null,
                cause: error,
            });
        }

        return data;
    }

    return {
        async scalar(fn, args) {
            return (await call(fn, args)) ?? null;
        },

        async rows(fn, args) {
            const data = await call(fn, args);

            if (!Array.isArray(data)) {
                throw new TypeError(`authz.${fn} did not return a set`);
            }

            return data as Row[];
        },
    };
}
