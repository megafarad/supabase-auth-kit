import type { Credentials } from "./index.js";

/** The header shape every Node HTTP framework exposes: lower-cased names, repeated headers as arrays. */
export type HeaderBag = Readonly<Record<string, string | string[] | undefined>>;

function bearerFrom(header: string | string[] | undefined): string | null {
    if (typeof header !== "string") {
        return null;
    }

    const [scheme, ...rest] = header.split(" ");

    // A non-Bearer scheme is not our credential; apps use Basic for unrelated things.
    if (scheme?.toLowerCase() !== "bearer") {
        return null;
    }

    const token = rest.join(" ").trim();

    return token.length > 0 ? token : null;
}

/**
 * Reads a request's credentials from its headers. Precedence between the two is not decided
 * here -- `resolvePrincipal` owns that -- so both are returned as found.
 *
 * An array-valued API-key header counts as no key: two values is an ambiguous request, and
 * picking one would let a caller steer which identity the server uses.
 */
export function credentialsFromHeaders(
    headers: HeaderBag,
    apiKeyHeader = "x-api-key",
): Credentials {
    const apiKey = headers[apiKeyHeader.toLowerCase()];

    return {
        apiKey: typeof apiKey === "string" && apiKey.length > 0 ? apiKey : null,
        bearer: bearerFrom(headers.authorization),
    };
}
