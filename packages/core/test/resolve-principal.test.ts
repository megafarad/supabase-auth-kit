import { describe, expect, it, vi } from "vitest";

import { createAuthKit } from "../src/index.js";
import { isInvalidToken } from "../src/identity.js";
import type { QueryFn, Row } from "../src/query.js";

const AUTH_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";

/**
 * Routes by which authz function the SQL mentions, so a test can say "the key resolves" or
 * "the user has no authz row" without caring about statement text.
 */
function routedQuery(handlers: {
    verifyApiKey?: string | null;
    principalForAuthUser?: string | null;
}): QueryFn & { seen: string[] } {
    const seen: string[] = [];

    const query = (async (sql: string): Promise<Row[]> => {
        if (sql.includes("verify_api_key")) {
            seen.push("verify_api_key");

            return [{ result: handlers.verifyApiKey ?? null }];
        }

        if (sql.includes("principal_for_auth_user")) {
            seen.push("principal_for_auth_user");

            return [{ result: handlers.principalForAuthUser ?? null }];
        }

        throw new Error(`unexpected sql: ${sql}`);
    }) as QueryFn & { seen: string[] };

    query.seen = seen;

    return query;
}

/**
 * Injects the verifier rather than patching the returned object: `resolvePrincipal` closes over
 * the verifier chosen at construction, so a spread override would leave the real JWKS one in
 * place and these would stop being unit tests.
 */
function kitWith(
    query: QueryFn,
    verifyBearer: (token: string) => Promise<string | null>,
) {
    return createAuthKit({ query, verifyBearer });
}

describe("resolvePrincipal", () => {
    it("reports no credential when none is sent", async () => {
        const query = routedQuery({});
        const kit = kitWith(query, async () => null);

        expect(await kit.resolvePrincipal({})).toEqual({
            principalId: null,
            kind: null,
            credentialPresented: false,
        });
        expect(query.seen).toEqual([]);
    });

    it("resolves an API key to an api_key principal", async () => {
        const query = routedQuery({ verifyApiKey: PRINCIPAL });
        const kit = kitWith(query, async () => null);

        expect(await kit.resolvePrincipal({ apiKey: "sak_x_y" })).toEqual({
            principalId: PRINCIPAL,
            kind: "api_key",
            credentialPresented: true,
        });
    });

    // verify_api_key writes last_used_at, so a second call would be a second row write.
    it("verifies an API key exactly once", async () => {
        const query = routedQuery({ verifyApiKey: PRINCIPAL });
        const kit = kitWith(query, async () => null);

        await kit.resolvePrincipal({ apiKey: "sak_x_y" });

        expect(query.seen).toEqual(["verify_api_key"]);
    });

    it("prefers the API key and never verifies the bearer when both are sent", async () => {
        const query = routedQuery({ verifyApiKey: PRINCIPAL });
        const verifyBearer = vi.fn(async () => AUTH_USER);
        const kit = kitWith(query, verifyBearer);

        await kit.resolvePrincipal({ apiKey: "sak_x_y", bearer: "token" });

        expect(verifyBearer).not.toHaveBeenCalled();
        expect(query.seen).toEqual(["verify_api_key"]);
    });

    it("treats a bad API key as presented-but-unresolved", async () => {
        const query = routedQuery({ verifyApiKey: null });
        const kit = kitWith(query, async () => null);

        expect(await kit.resolvePrincipal({ apiKey: "sak_nope" })).toEqual({
            principalId: null,
            kind: null,
            credentialPresented: true,
        });
    });

    it("resolves a valid bearer to a user principal", async () => {
        const query = routedQuery({ principalForAuthUser: PRINCIPAL });
        const kit = kitWith(query, async () => AUTH_USER);

        expect(await kit.resolvePrincipal({ bearer: "token" })).toEqual({
            principalId: PRINCIPAL,
            kind: "user",
            credentialPresented: true,
        });
    });

    /**
     * The case the model doc calls out as open question 1. Registering an address a retired
     * identity still holds yields a confirmed auth.users row and nothing in authz. That caller
     * is authenticated with zero authority -- not an error, and not anonymous either.
     */
    it("treats a verified token with no authz identity as presented-but-unresolved", async () => {
        const query = routedQuery({ principalForAuthUser: null });
        const kit = kitWith(query, async () => AUTH_USER);

        expect(await kit.resolvePrincipal({ bearer: "token" })).toEqual({
            principalId: null,
            kind: null,
            credentialPresented: true,
        });
        expect(query.seen).toEqual(["principal_for_auth_user"]);
    });

    it("does not look up a principal when the token fails verification", async () => {
        const query = routedQuery({ principalForAuthUser: PRINCIPAL });
        const kit = kitWith(query, async () => null);

        expect(await kit.resolvePrincipal({ bearer: "forged" })).toEqual({
            principalId: null,
            kind: null,
            credentialPresented: true,
        });
        expect(query.seen).toEqual([]);
    });

    it("ignores empty-string credentials", async () => {
        const query = routedQuery({});
        const kit = kitWith(query, async () => AUTH_USER);

        expect(
            (await kit.resolvePrincipal({ bearer: "", apiKey: "" }))
                .credentialPresented,
        ).toBe(false);
        expect(query.seen).toEqual([]);
    });
});

describe("bearer error classification", () => {
    // A rejected token is a null. A JWKS outage is not -- folding it into null would turn an
    // infrastructure fault into a wall of 401s that reads as a client problem.
    it("classifies token problems as invalid", () => {
        for (const code of [
            "ERR_JWT_EXPIRED",
            "ERR_JWT_CLAIM_VALIDATION_FAILED",
            "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
            "ERR_JWKS_NO_MATCHING_KEY",
            "ERR_JOSE_ALG_NOT_ALLOWED",
        ]) {
            expect(isInvalidToken(Object.assign(new Error("x"), { code }))).toBe(
                true,
            );
        }
    });

    it("does not classify infrastructure or unknown failures as invalid", () => {
        for (const error of [
            Object.assign(new Error("timeout"), { code: "ERR_JWKS_TIMEOUT" }),
            Object.assign(new Error("dns"), { code: "ENOTFOUND" }),
            new TypeError("fetch failed"),
            null,
            undefined,
        ]) {
            expect(isInvalidToken(error)).toBe(false);
        }
    });
});
