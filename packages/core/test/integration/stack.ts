/**
 * The local stack the integration suites run against, and the two transports they run over.
 *
 * Each suite skips itself when what it needs is unreachable, so `npm run test` stays green
 * without Docker. CI verifies both the database and the API are up before testing, so a skip
 * there cannot pass for a green run.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { createClient } from "@supabase/supabase-js";
import { Client } from "pg";

import { fromQuery, fromSupabase, type AuthzTransport } from "../../src/index.js";

export const DB_URL =
    process.env["AUTHZ_TEST_DATABASE_URL"] ??
    "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

export const SUPABASE_URL =
    process.env["AUTHZ_TEST_SUPABASE_URL"] ?? "http://127.0.0.1:54321";

/**
 * The local stack's own keys, read from `supabase status` when the environment does not supply
 * them. They are fixed development values, but they are not written down here: secret scanning
 * rightly cannot tell a local key from a real one.
 */
function localStackKeys(): Record<string, string> {
    try {
        const output = execFileSync(
            "npx",
            ["supabase", "status", "-o", "json", "--workdir", INSTALLER_DIR],
            { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 30_000, shell: true },
        );

        return JSON.parse(output.slice(output.indexOf("{"))) as Record<string, string>;
    } catch {
        return {};
    }
}

const INSTALLER_DIR = fileURLToPath(new URL("../../../../apps/installer", import.meta.url));

const needsLocalKeys =
    process.env["AUTHZ_TEST_SUPABASE_SECRET_KEY"] === undefined ||
    process.env["AUTHZ_TEST_SUPABASE_PUBLISHABLE_KEY"] === undefined;

const local = needsLocalKeys ? localStackKeys() : {};

export const SECRET_KEY =
    process.env["AUTHZ_TEST_SUPABASE_SECRET_KEY"] ?? local["SECRET_KEY"] ?? "";

export const PUBLISHABLE_KEY =
    process.env["AUTHZ_TEST_SUPABASE_PUBLISHABLE_KEY"] ?? local["PUBLISHABLE_KEY"] ?? "";

export const ADMIN_ROLE = "a0000000-0000-4000-8000-000000000002";
export const TENANT_ADMIN_ROLE = "a0000000-0000-4000-8000-000000000003";

async function databaseReachable(): Promise<boolean> {
    const probe = new Client({ connectionString: DB_URL });

    try {
        await probe.connect();
        await probe.end();

        return true;
    } catch {
        return false;
    }
}

/** Reachable, and exposing authz: an API that is up but not configured is not usable either. */
async function apiReachable(): Promise<boolean> {
    if (SECRET_KEY === "" || PUBLISHABLE_KEY === "") {
        return false;
    }

    try {
        const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/has_scope`, {
            method: "POST",
            headers: {
                apikey: SECRET_KEY,
                "Content-Profile": "authz",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                p_principal_id: null,
                p_tenant_id: null,
                p_scope: "probe",
            }),
            signal: AbortSignal.timeout(3000),
        });

        return response.ok;
    } catch {
        return false;
    }
}

export const databaseAvailable = await databaseReachable();
export const apiAvailable = databaseAvailable && (await apiReachable());

export function secretClient() {
    return createClient(SUPABASE_URL, SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
    });
}

export interface TransportCase {
    name: string;
    available: boolean;
    /** `client` is the fixture connection; the pg transport reuses it. */
    make(client: Client): AuthzTransport;
}

/** Every suite that takes a transport runs once per entry. */
export const TRANSPORTS: TransportCase[] = [
    {
        name: "pg",
        available: databaseAvailable,
        make: client =>
            fromQuery((sql, params) =>
                client.query(sql, params as unknown[]).then(r => r.rows),
            ),
    },
    {
        name: "supabase-js",
        available: apiAvailable,
        make: () => fromSupabase(secretClient()),
    },
];

/** A single `result` column from a fixture statement. */
export async function one<T>(client: Client, sql: string, params: unknown[] = []): Promise<T> {
    const { rows } = await client.query(sql, params);

    return rows[0].result as T;
}

export function suffix(): string {
    return Math.random().toString(36).slice(2, 10);
}
