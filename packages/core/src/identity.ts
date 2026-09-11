import { createRemoteJWKSet, jwtVerify } from "jose";

import { scalar, type QueryFn } from "./query.js";
import { isUuid } from "./uuid.js";

export interface JwtOptions {
    /** Supabase's JWKS endpoint, e.g. `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`. */
    jwksUrl: string;
    /** Expected `iss`. Supabase uses `${SUPABASE_URL}/auth/v1`. Unchecked when omitted. */
    issuer?: string;
    /** Expected `aud`. Supabase signs user tokens with `authenticated`. */
    audience?: string;
    /**
     * Accepted signing algorithms. Defaults to the asymmetric pair Supabase issues.
     *
     * **Never add HS256.** A JWKS publishes public keys, and an attacker who MACs a token with
     * a public key's raw bytes as the HMAC secret defeats verification entirely if a symmetric
     * algorithm is accepted -- the textbook algorithm-confusion attack. jose would refuse to
     * derive a symmetric key from a JWKS anyway, but pinning the list costs nothing and states
     * the intent where someone might otherwise widen it.
     */
    algorithms?: string[];
    /**
     * Token `role` claims to refuse. Supabase's own `anon` and `service_role` API keys are
     * themselves JWTs; the asymmetric scheme already rejects them since they are HS256-signed,
     * but they get pasted into Authorization headers often enough to be worth naming.
     */
    rejectRoles?: string[];
}

/**
 * jose error codes that mean "this token is not acceptable". Anything else -- a JWKS fetch
 * failure, a timeout, a programming error -- is rethrown rather than folded into null.
 *
 * That distinction matters: swallowing a JWKS outage would turn every request into a 401,
 * which reads to the caller as a credential problem and hides the real fault.
 */
const INVALID_TOKEN_CODES: ReadonlySet<string> = new Set([
    "ERR_JWT_EXPIRED",
    "ERR_JWT_CLAIM_VALIDATION_FAILED",
    "ERR_JWT_INVALID",
    "ERR_JWS_INVALID",
    "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
    "ERR_JWKS_NO_MATCHING_KEY",
    "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
    "ERR_JOSE_ALG_NOT_ALLOWED",
]);

/** Exported for testing; not part of the package's public surface via `index.ts`. */
export function isInvalidToken(error: unknown): boolean {
    const code = (error as { code?: unknown } | null)?.code;

    return typeof code === "string" && INVALID_TOKEN_CODES.has(code);
}

export type VerifyBearer = (token: string) => Promise<string | null>;

/**
 * Verifies a Supabase access token and returns its subject -- the `auth.users` id -- or null
 * if the token is not acceptable.
 *
 * Verification is local and asymmetric. Supabase issues ES256 tokens signed with a key served
 * from JWKS, so this is not the legacy HS256 shared secret. jose caches the key set and
 * refreshes it on an unknown `kid`.
 */
export function createBearerVerifier(options: JwtOptions): VerifyBearer {
    // Built once, never per request: this object *is* the key cache. It holds the fetched JWKS
    // in process, refetches on an unseen `kid`, and rate-limits that refetch so a flood of
    // bad-kid tokens cannot be turned into an amplifier against the auth endpoint.
    const jwks = createRemoteJWKSet(new URL(options.jwksUrl));

    const algorithms = options.algorithms ?? ["ES256", "RS256"];
    const rejectRoles = new Set(
        options.rejectRoles ?? ["service_role", "anon"],
    );

    return async function verifyBearer(token) {
        try {
            const { payload } = await jwtVerify(token, jwks, {
                issuer: options.issuer,
                audience: options.audience ?? "authenticated",
                algorithms,
            });

            const role = payload["role"];

            if (typeof role === "string" && rejectRoles.has(role)) {
                return null;
            }

            // Validated here so a malformed subject never reaches Postgres, where it would be
            // a 22P02 cast error -- a 500 for what is really a bad credential.
            return isUuid(payload.sub) ? payload.sub : null;
        } catch (error) {
            if (isInvalidToken(error)) {
                return null;
            }

            throw error;
        }
    };
}

/**
 * The `auth.users` id behind a token, mapped to an authz principal.
 *
 * Delegates to SQL rather than selecting from the tables, so the disabled / deleted /
 * unclaimed filters live in exactly one place. A null here is a legitimate state, not an
 * error: someone who registers an address a retired identity still holds gets a confirmed
 * `auth.users` row and nothing in authz.
 */
export function principalForAuthUser(
    query: QueryFn,
    authUserId: string,
): Promise<string | null> {
    return scalar<string>(
        query,
        "select authz.principal_for_auth_user($1) as result",
        [authUserId],
    );
}

/**
 * The principal behind an API key, or null if the key is unknown, wrong, revoked or expired --
 * SQL returns null for all four without saying which.
 *
 * `authz.verify_api_key` is VOLATILE: it writes `last_used_at`, so this costs one row-level
 * write per call. Call it at most once per request.
 */
export function principalForApiKey(
    query: QueryFn,
    key: string,
): Promise<string | null> {
    return scalar<string>(query, "select authz.verify_api_key($1) as result", [
        key,
    ]);
}

/** Whether a claimed, enabled user or a live API key sits behind a principal. */
export async function principalIsActive(
    query: QueryFn,
    principalId: string,
): Promise<boolean> {
    return (
        (await scalar<boolean>(
            query,
            "select authz.principal_is_active($1) as result",
            [principalId],
        )) === true
    );
}
