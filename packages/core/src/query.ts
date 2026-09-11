/**
 * The database seam.
 *
 * Bring-your-own: the consumer supplies a function that runs parameterized SQL and returns
 * rows, so this package depends on no driver and can sit on a pool the app already has.
 *
 *   pg:           (sql, params) => pool.query(sql, params).then(r => r.rows)
 *   postgres.js:  (sql, params) => sql.unsafe(sql, params as never[])
 *
 * The connection must reach the private `authz` schema, which means a direct Postgres
 * connection — the owner (`postgres`) connection string, not the service key. `service_role`
 * is NOLOGIN in Supabase and only reaches tables through PostgREST, which does not expose
 * `authz`. That connection bypasses RLS, so the SECURITY DEFINER functions are the only
 * enforcement: never issue direct DML against authz tables.
 *
 * Values must come back as native JavaScript types (both pg and postgres.js do this) — a
 * driver that stringifies booleans would make `hasScope` read false, which fails closed but
 * silently denies.
 */
export type Row = Record<string, unknown>;

export type QueryFn = (
    sql: string,
    params: readonly unknown[],
) => Promise<Row[]>;

/**
 * Reads a single value. Every query in this package aliases its output `result`, so
 * extraction never depends on a driver's column-naming behaviour.
 */
export async function scalar<T>(
    query: QueryFn,
    sql: string,
    params: readonly unknown[],
): Promise<T | null> {
    const rows = await query(sql, params);
    const value = rows[0]?.["result"];

    return value === undefined ? null : (value as T);
}

/** Reads one column across every row, again via the `result` alias. */
export async function column<T>(
    query: QueryFn,
    sql: string,
    params: readonly unknown[],
): Promise<T[]> {
    const rows = await query(sql, params);

    return rows.map(row => row["result"] as T);
}
