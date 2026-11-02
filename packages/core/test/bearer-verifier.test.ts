import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { createBearerVerifier } from "../src/identity.js";

const AUTH_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const JWKS_URL = "https://project.example/auth/v1/.well-known/jwks.json";

describe("createBearerVerifier assurance level", () => {
    let sign: (claims: Record<string, unknown>) => Promise<string>;

    beforeAll(async () => {
        const { publicKey, privateKey } = await generateKeyPair("ES256");
        const jwk = { ...(await exportJWK(publicKey)), kid: "test", alg: "ES256", use: "sig" };

        vi.stubGlobal("fetch", async () => Response.json({ keys: [jwk] }));

        sign = claims =>
            new SignJWT(claims)
                .setProtectedHeader({ alg: "ES256", kid: "test" })
                .setSubject(AUTH_USER)
                .setAudience("authenticated")
                .setExpirationTime("5m")
                .sign(privateKey);
    });

    afterAll(() => {
        vi.unstubAllGlobals();
    });

    it.each([
        ["aal1", { aal: "aal1" }, "aal1"],
        ["aal2", { aal: "aal2" }, "aal2"],
        ["a missing claim", {}, null],
        ["an unknown level", { aal: "aal3" }, null],
        ["a non-string claim", { aal: 2 }, null],
    ])("reads %s", async (_label, claims, expected) => {
        const verify = createBearerVerifier({ jwksUrl: JWKS_URL });

        expect(await verify(await sign(claims))).toEqual({
            authUserId: AUTH_USER,
            aal: expected,
        });
    });
});
