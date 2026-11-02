/**
 * The claim the aal2 guards rely on, taken from the real Auth server rather than assumed: a TOTP
 * factor is enrolled and verified through supabase-js, and the resulting tokens are read by the
 * real JWKS verifier. Needs `[auth.mfa.totp]` enabled, which `config.toml` does for the local stack.
 */
import { createHmac } from "node:crypto";

import { createClient } from "@supabase/supabase-js";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createAuthKit, type AuthKit } from "../../src/index.js";
import {
    DB_URL,
    PUBLISHABLE_KEY,
    SUPABASE_URL,
    apiAvailable,
    secretClient,
    suffix,
} from "./stack.js";

function base32Decode(input: string): Buffer {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";

    for (const character of input.replace(/=+$/, "").toUpperCase()) {
        bits += alphabet.indexOf(character).toString(2).padStart(5, "0");
    }

    const bytes = bits.match(/.{8}/g) ?? [];

    return Buffer.from(bytes.map(byte => parseInt(byte, 2)));
}

/** RFC 6238 with the parameters Supabase issues: SHA-1, 30 seconds, six digits. */
function totp(secret: string, now = Date.now()): string {
    const counter = Buffer.alloc(8);

    counter.writeBigUInt64BE(BigInt(Math.floor(now / 30_000)));

    const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
    const offset = (digest[digest.length - 1] as number) & 0x0f;
    const code = digest.readUInt32BE(offset) & 0x7fffffff;

    return String(code % 1_000_000).padStart(6, "0");
}

describe.skipIf(!apiAvailable)("TOTP against the local Auth server", () => {
    const email = `mfa-${suffix()}@example.com`;
    const password = `pw-${suffix()}-${suffix()}`;
    const admin = secretClient();
    const browser = createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
    });

    let db: Client;
    let kit: AuthKit;
    let authUserId: string;

    async function accessToken(): Promise<string> {
        const { data, error } = await browser.auth.getSession();

        expect(error).toBeNull();

        return data.session?.access_token as string;
    }

    beforeAll(async () => {
        db = new Client({ connectionString: DB_URL });
        await db.connect();

        kit = createAuthKit({
            query: (sql, params) => db.query(sql, params as unknown[]).then(r => r.rows),
            jwt: {
                jwksUrl: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
                issuer: `${SUPABASE_URL}/auth/v1`,
            },
        });

        const created = await admin.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
        });

        expect(created.error).toBeNull();
        authUserId = created.data.user?.id as string;

        const signedIn = await browser.auth.signInWithPassword({ email, password });

        expect(signedIn.error).toBeNull();
    });

    afterAll(async () => {
        if (authUserId !== undefined) {
            await admin.auth.admin.deleteUser(authUserId);
        }

        await db?.end();
    });

    it("moves a user from aal1 to aal2 by verifying a factor", async () => {
        const before = await kit.resolvePrincipal({ bearer: await accessToken() });

        expect(before.kind).toBe("user");
        expect(before.aal).toBe("aal1");

        const enrolled = await browser.auth.mfa.enroll({ factorType: "totp" });

        expect(enrolled.error).toBeNull();

        // Enrolling alone proves nothing about possession, so it must not raise the level.
        const pending = await kit.resolvePrincipal({ bearer: await accessToken() });

        expect(pending.aal).toBe("aal1");

        const factorId = enrolled.data?.id as string;
        const verified = await browser.auth.mfa.challengeAndVerify({
            factorId,
            code: totp(enrolled.data?.totp.secret as string),
        });

        expect(verified.error).toBeNull();

        const after = await kit.resolvePrincipal({ bearer: await accessToken() });

        expect(after.principalId).toBe(before.principalId);
        expect(after.aal).toBe("aal2");
    });
});
