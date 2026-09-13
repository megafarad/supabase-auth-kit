/**
 * The driver seam, for the Postgres transport (`fromQuery` in `transport.ts`).
 *
 * Bring-your-own: the consumer supplies a function that runs parameterized SQL and returns
 * rows, so this package depends on no driver and can sit on a pool the app already has.
 *
 *   pg:           (sql, params) => pool.query(sql, params).then(r => r.rows)
 *   postgres.js:  (sql, params) => sql.unsafe(sql, params as never[])
 *
 * The connection must be able to execute the `authz` functions, which in practice means the
 * owner (`postgres`) connection string. It bypasses RLS, so the SECURITY DEFINER functions are
 * the only enforcement: every statement core sends is a single call to one of them, and nothing
 * else should issue DML against authz tables with it. Apps already on supabase-js can skip all
 * of this and use `fromSupabase` instead.
 *
 * Values must come back as native JavaScript types (both pg and postgres.js do this) -- a
 * driver that stringifies booleans would make `hasScope` read false, which fails closed but
 * silently denies.
 */
export type Row = Record<string, unknown>;

export type QueryFn = (
    sql: string,
    params: readonly unknown[],
) => Promise<Row[]>;
