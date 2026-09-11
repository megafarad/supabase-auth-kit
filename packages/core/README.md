# @sirhc77/supabase-auth-kit-core

The framework-agnostic core of [`@sirhc77/supabase-auth-kit`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit). It verifies Supabase access tokens, resolves API keys, answers scope checks, and exposes the kit's write functions, all by calling the `authz` SQL functions the kit installs.

**Most apps don't need to install this directly.** The [Express](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-express) and [Fastify](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-fastify) adapters depend on it and re-export what you need. Use core directly to:

- check authorization outside an HTTP request, for example in jobs, queue workers or scripts, or
- write a binding for another framework, such as Hono, Koa or Next.js route handlers.

Install the SQL first. See [Install](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit#install) in the main package.

## Install

```bash
npm install @sirhc77/supabase-auth-kit-core pg
```

Its only runtime dependency is [`jose`](https://github.com/panva/jose). It depends on no database driver: you pass in a query function, and `pg` above is only an example. The package is ESM-only.

## Create a kit

```ts
import pg from "pg";
import { createAuthKit } from "@sirhc77/supabase-auth-kit-core";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const kit = createAuthKit({
    query: (text, params) => pool.query(text, [...params]).then(r => r.rows),
    jwt: {
        jwksUrl: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
        issuer: `${process.env.SUPABASE_URL}/auth/v1`,
    },
});
```

With `postgres.js`, pass `query: (text, params) => sql.unsafe(text, params as never[])` instead.

`DATABASE_URL` is your project's Postgres connection string, for the **`postgres`** role. You'll find it under *Connect* in the Supabase dashboard, and a local stack uses `postgresql://postgres:postgres@127.0.0.1:54322/postgres`. The Supabase service-role key won't work: the `authz` schema is private and can't be reached through the Supabase APIs.

That connection bypasses row-level security. Every statement this package sends is a call to an `authz` function, and those functions enforce the rules. Don't write to `authz` tables with it yourself.

### Options

| Option | |
| --- | --- |
| `query` | **Required.** `(sql, params) => Promise<Row[]>`. Values must come back as native types, which `pg` and `postgres.js` both do. A driver that returned booleans as strings would make every scope check read as false |
| `jwt.jwksUrl` | Supabase's JWKS endpoint, `<SUPABASE_URL>/auth/v1/.well-known/jwks.json` |
| `jwt.issuer` | The expected `iss`: `<SUPABASE_URL>/auth/v1`. The issuer isn't checked when you omit it, so set it |
| `jwt.audience` | The expected `aud`. Defaults to `authenticated` |
| `jwt.algorithms` | Defaults to `["ES256", "RS256"]`. Never add `HS256`: accepting it alongside a JWKS lets anyone forge a token |
| `jwt.rejectRoles` | Token `role` claims to refuse. Defaults to `["service_role", "anon"]` |
| `verifyBearer` | Your own verifier, `(token) => Promise<authUserId \| null>`, used instead of `jwt`. Use it if you already verify tokens elsewhere, such as at a gateway or with `supabase.auth.getUser` |

You must pass either `jwt` or `verifyBearer`, or `createAuthKit` throws. With `jwt`, tokens are verified locally against a cached copy of the key set, so verifying a token doesn't call Supabase Auth. An invalid, expired or wrongly signed token verifies as `null`. If the key set itself can't be fetched, the error is thrown: an outage shouldn't look like every client sending a bad token.

## Checking authorization

```ts
const principalId = await kit.principalForAuthUser(authUserId);

if (await kit.hasScope(principalId, tenantId, "reports.run")) {
    // ...
}
```

| Method | |
| --- | --- |
| `hasScope(principalId, tenantId, scope)` | Whether the principal holds the scope at the tenant |
| `effectiveScopes(principalId, tenantId)` | Every scope name the principal holds there |
| `verifyBearer(token)` | The Supabase user ID behind an access token, or `null` |
| `principalForAuthUser(authUserId)` | The principal behind a Supabase user ID. `null` if there's no identity, or it's unclaimed, disabled or deleted |
| `principalForApiKey(key)` | The principal behind a plaintext API key. `null` if the key is unknown, wrong, revoked or expired. Updates the key's `last_used_at`, so call it once per request |
| `principalIsActive(principalId)` | Whether a claimed, enabled user or a live API key is behind the principal |
| `resolvePrincipal({ bearer, apiKey })` | Turns request credentials into `{ principalId, kind, credentialPresented }`. See [Credentials](#credentials) |
| `as(actorPrincipalId)` | The write API, acting as that principal. See [Writes](#writes) |

`hasScope` and `effectiveScopes` accept a `null` principal or tenant and answer `false` or `[]` without querying. That's the same answer the SQL would give. Scope names are compared exactly as written.

Nothing is cached between calls. A revoked grant takes effect on the very next check.

### Credentials

`resolvePrincipal` is how the adapters authenticate a request. Pass it whichever credentials the request carried:

| Request carried | `principalId` | `credentialPresented` | An adapter answers |
| --- | --- | --- | --- |
| Nothing | `null` | `false` | 401 |
| A credential that maps to no principal | `null` | `true` | 403 |
| A credential that maps to a principal | the ID | `true` | Depends on the scope check |

The second row is a real state, not only a bad credential. Someone who registers an address that belonged to a deleted account has a valid Supabase token but no authorization identity. They're authenticated, but they hold no authority.

If both an API key and a bearer token are passed, the API key is used and the token is ignored.

## Writes

`kit.as(actor)` returns the kit's write functions with the actor already bound, so the actor can't be passed wrongly on an individual call. All rules are enforced in SQL. For example, nobody can grant a role that has scopes they don't hold themselves.

```ts
const writes = kit.as(actorPrincipalId);

const tenantId = await writes.createTenant(parentTenantId, "Engineering");
await writes.inviteUser(tenantId, "new.hire@example.com", roleId);
```

| Method | |
| --- | --- |
| `grantRole(principalId, roleId, tenantId, expiresAt?)` | Returns the binding ID. Granting a revoked role again reinstates it |
| `inviteUser(tenantId, email, roleId)` | Returns the user ID. Creates an identity if the address has none |
| `revokeBinding(bindingId)` | Idempotent |
| `createRole(tenantId, name, description, crossesBoundary?)` | Returns the role ID. `crossesBoundary` needs authority at the master tenant |
| `updateRole(roleId, { name?, description?, crossesBoundary? })` | Omitted fields are left alone |
| `addRoleScope(roleId, scopeId)` / `removeRoleScope(roleId, scopeId)` | |
| `createScope(tenantId, name, description?)` | Returns the scope ID. `authz.`-prefixed names are reserved to the master tenant |
| `createTenant(parentId, name)` | Returns the tenant ID |
| `createWorkspace(name)` | Returns the tenant ID. The only write with no scope check, so gate it yourself |
| `updateTenant(tenantId, { name?, inherit? })` | Changing `inherit` needs authority at the parent |
| `createApiKey(tenantId, label, expiresAt?)` | Returns the plaintext key. It's shown only this once |
| `revokeApiKey(apiKeyId)` | Idempotent |

### Errors

Database failures from writes are rethrown as typed errors. Each keeps the SQLSTATE as `sqlState` and the original error as `cause`:

| Class | SQLSTATE | Meaning |
| --- | --- | --- |
| `AuthzDeniedError` | `P0001` | A rule refused the write. The message doesn't say why, so it can't reveal whether a role or tenant exists |
| `AuthzStateError` | `P0002`, `P0003` | The schema isn't in the expected state. Usually the kit's migrations haven't been applied |
| `AuthzConflictError` | `23505` | The write collided with an existing row |
| `AuthzUsageError` | `23503`, `23514` | A bad ID or an impossible combination of arguments |

All four extend `AuthKitError`. Any other error, such as a dropped connection, is rethrown unchanged.

## Writing a binding

The HTTP layer the adapters share is exported, so a new binding only has to adapt it to its framework's request type. Here it is with the Fetch API's `Request`:

```ts
import {
    checkScope,
    createAuthzContext,
    credentialsFromHeaders,
    enforceGuard,
    statusOf,
} from "@sirhc77/supabase-auth-kit-core";

async function handle(request: Request, tenantId: string | undefined): Promise<Response> {
    const resolved = await kit.resolvePrincipal(
        credentialsFromHeaders(Object.fromEntries(request.headers)),
    );
    const context = createAuthzContext(kit, resolved);

    try {
        await enforceGuard(context, () => tenantId, checkScope("invoices.read"));
    } catch (error) {
        const mapped = statusOf(error);
        if (mapped === null) throw error;
        return Response.json({ error: mapped.code }, { status: mapped.status });
    }

    return Response.json({ principalId: context.principalId });
}
```

| Export | |
| --- | --- |
| `credentialsFromHeaders(headers, apiKeyHeader?)` | Reads `Authorization: Bearer …` and the API-key header (default `x-api-key`) from lower-cased headers. A repeated API-key header counts as no key |
| `createAuthzContext(kit, resolved)` | The per-request context: `principalId`, `kind`, `credentialPresented`, `has(tenant, scope)`, `scopes(tenant)` and `as`. Create one per request and never reuse it: it caches scope lookups for the request's lifetime |
| `enforceGuard(context, resolveTenant, check)` | The guard, in a fixed order: 401 with no credential, 403 for a credential with no principal, 400 for a missing or malformed tenant, then `check` |
| `checkScope(scope)`, `checkAllScopes(scopes)`, `checkAnyScope(scopes)` | Ready-made checks. Each makes at most one database round trip per tenant per request. Write your own as a `GuardCheck`, `(context, tenantId) => Promise<void>`, that throws to deny |
| `tenantFromParam`, `tenantFromHeader`, `tenantFromQuery`, `tenantFromBody` | Tenant resolvers over any request with `params`, `query`, `body` and `headers`. Each returns nothing unless the value is a UUID |
| `HttpAuthzError` and its subclasses | `UnauthenticatedError` (401), `ForbiddenError` (403), `TenantRequiredError` (400) and `MiddlewareNotInstalledError` (500). Each carries `status` and `code` |
| `statusOf(error)` | `{ status, code }` for any kit error, `null` for anything else. `AuthzDeniedError` maps to 403 and other `AuthKitError`s to 500 |
| `isUuid(value)` | The UUID check the helpers use. Validate any ID with it before it reaches SQL, because a malformed UUID is a database error, which surfaces as a 500 |

`enforceGuard` doesn't handle a missing context itself: when the authentication step didn't run, the binding should throw `MiddlewareNotInstalledError`, with a message explaining how to fix the wiring in that framework. Don't skip the guard when the context is missing, and don't substitute an empty context either. A wiring mistake should be a loud 500, not a quiet 401 or an unguarded route.

## License

MIT
