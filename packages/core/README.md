# @sirhc77/supabase-auth-kit-core

The framework-agnostic core of [`@sirhc77/supabase-auth-kit`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit). It verifies Supabase access tokens, resolves API keys, answers scope checks, and exposes the kit's read and write functions, all by calling the `authz` SQL functions the kit installs.

**Most apps don't need to install this directly.** The [Express](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-express) and [Fastify](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-fastify) adapters depend on it and re-export what you need. Use core directly to:

- check authorization outside an HTTP request, for example in jobs, queue workers or scripts, or
- write a binding for another framework, such as Hono, Koa or Next.js route handlers.

Install the SQL first. See [Install](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit#install) in the main package.

## Install

```bash
npm install @sirhc77/supabase-auth-kit-core @supabase/supabase-js
```

Its only runtime dependency is [`jose`](https://github.com/panva/jose). It doesn't depend on supabase-js or on any database driver: you pass in the client you already have. The package is ESM-only.

## Create a kit

The kit reaches the database one of two ways. Pick one.

### With supabase-js

```ts
import { createClient } from "@supabase/supabase-js";
import { createAuthKit } from "@sirhc77/supabase-auth-kit-core";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SECRET_KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
});

const kit = createAuthKit({
    supabase,
    jwt: {
        jwksUrl: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
        issuer: `${process.env.SUPABASE_URL}/auth/v1`,
    },
});
```

This needs two things:

- **The secret key** (`sb_secret_…`, or the legacy `service_role` key). It can act as any principal, so it must never reach a browser. A publishable or anon key gets `AuthzConfigError`, and so does a client that has signed a user in, because supabase-js then sends the user's token instead of the key.
- **`authz` exposed to the API.** Locally, add `"authz"` to `schemas` under `[api]` in `supabase/config.toml` and restart the stack. On a hosted project, add it to the exposed schemas in the dashboard's API settings.

> **Grant nothing yourself.** The kit's migrations already give `service_role` exactly the functions it needs, and nothing else. Supabase's guide to exposing a custom schema tells you to grant its routines to `anon` and `authenticated`. Don't do that for `authz`: it would let anyone holding your public key call functions such as `provision_admin`, which makes the caller a platform administrator.

A client created with generated database types works too, without a cast.

### With a Postgres connection

```ts
import pg from "pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const kit = createAuthKit({
    query: (text, params) => pool.query(text, [...params]).then(r => r.rows),
    jwt: { /* as above */ },
});
```

With `postgres.js`, pass `query: (text, params) => sql.unsafe(text, params as never[])` instead.

`DATABASE_URL` is your project's Postgres connection string, for the **`postgres`** role. You'll find it under *Connect* in the Supabase dashboard, and a local stack uses `postgresql://postgres:postgres@127.0.0.1:54322/postgres`. This way needs no exposed schema.

Either way, the connection bypasses row-level security. Every call this package makes is to an `authz` function, and those functions enforce the rules. Don't write to `authz` tables yourself.

### Options

| Option | |
| --- | --- |
| `supabase` | A supabase-js client holding the secret key. See [With supabase-js](#with-supabase-js) |
| `query` | `(sql, params) => Promise<Row[]>` on a `postgres` connection. Values must come back as native types, which `pg` and `postgres.js` both do. A driver that returned booleans as strings would make every scope check read as false |
| `transport` | Your own `AuthzTransport`. `fromSupabase(client)` and `fromQuery(fn)` build the two above |
| `jwt.jwksUrl` | Supabase's JWKS endpoint, `<SUPABASE_URL>/auth/v1/.well-known/jwks.json` |
| `jwt.issuer` | The expected `iss`: `<SUPABASE_URL>/auth/v1`. The issuer isn't checked when you omit it, so set it |
| `jwt.audience` | The expected `aud`. Defaults to `authenticated` |
| `jwt.algorithms` | Defaults to `["ES256", "RS256"]`. Never add `HS256`: accepting it alongside a JWKS lets anyone forge a token |
| `jwt.rejectRoles` | Token `role` claims to refuse. Defaults to `["service_role", "anon"]` |
| `verifyBearer` | Your own verifier, `(token) => Promise<authUserId \| null>`, used instead of `jwt`. Use it if you already verify tokens elsewhere, such as at a gateway or with `supabase.auth.getUser` |

Pass exactly one of `supabase`, `query` or `transport`, and either `jwt` or `verifyBearer`, or `createAuthKit` throws. With `jwt`, tokens are verified locally against a cached copy of the key set, so verifying a token doesn't call Supabase Auth. An invalid, expired or wrongly signed token verifies as `null`. If the key set itself can't be fetched, the error is thrown: an outage shouldn't look like every client sending a bad token.

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
| `as(actorPrincipalId)` | The read and write APIs, acting as that principal. See [Reads](#reads) and [Writes](#writes) |

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

## Reads

`kit.as(actor)` also returns read functions, answered as that principal. Someone without the authority gets an empty result, never an error, so a read can't be used to find out whether a tenant or role exists.

```ts
const me = kit.as(principalId);

const { rows: myTenants } = await me.listMyBindings();       // for a tenant switcher
const { rows: members, nextCursor } = await me.listTenantBindings(tenantId, { limit: 50 });
const next = await me.listTenantBindings(tenantId, { limit: 50, after: nextCursor });
```

| Method | Returns | Needs, at the tenant |
| --- | --- | --- |
| `getTenant(tenantId)` | The tenant, or `null` | `authz.tenants.read` |
| `listChildTenants(parentId, page?)` | Child tenants, by name. Meant for administrators of the parent | `authz.tenants.read` at each child |
| `listMyBindings(page?)` | Your own live bindings, with tenant and role names. How to find the tenants you belong to | Nothing |
| `listPrincipalBindings(principalId, page?)` | Another principal's live bindings | `authz.bindings.read` where each was made |
| `listTenantBindings(tenantId, { includeInherited?, ...page }?)` | The tenant's members, by email or key label, pending invites included (`claimed: false`). `includeInherited` adds bindings made higher up the tree, platform administrators among them | `authz.bindings.read` where each was made. Your own binding is always shown |
| `listRoles(tenantId, page?)` | Roles in effect after shadowing, with `inherited` marking ones defined higher up | `authz.roles.read` |
| `listRoleScopes(tenantId, roleId, page?)` | The scopes a role confers, including an inherited role such as `tenant_admin` | `authz.roles.read` |
| `listScopes(tenantId, page?)` | Scope definitions in effect after shadowing | `authz.scopes.read` |
| `listApiKeys(tenantId, page?)` | Keys issued at the tenant, revoked ones included. Never the key hash | `authz.api_keys.read` |
| `listAuditLogs(filter?)` | The audit trail, newest first. See [Audit log](#audit-log) | `authz.audit.read` |

Lists return `{ rows, nextCursor }`. Pass `nextCursor` back as `after` to get the next page; it's `null` once a page comes back short. `limit` defaults to 100 and is capped at 1000. Treat cursors as opaque: a malformed one throws `AuthzUsageError`.

Row fields use the SQL column names, such as `tenant_id` and `crosses_boundary`, and timestamps are ISO-8601 strings. Some fields are `null` when you lack the scope to see them. In `listTenantBindings`, for example, `email` needs `authz.users.read` and `role_name` needs `authz.roles.read` where the binding was made.

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
| `logAudit(entry)` | Appends an audit row. Never throws: resolves to the row ID, or `null` if the write failed |

## Audit log

Every write above records itself, in the same transaction as the change, so the log can't disagree with what actually happened. You don't have to call anything.

What the database can't see is the request, so pass it when you bind the actor — the framework adapters do this for you:

```ts
const writes = kit.as(actorPrincipalId, {
    requestId: req.id,
    method: req.method,
    route: "/tenants/:id/members",
    ip: req.ip,
    userAgent: req.headers["user-agent"],
});
```

**Refusals are recorded too.** A write the SQL guards refuse, and a request a scope guard turns away, both leave a row with `outcome: "denied"` and the refusal's message in `reason`. This can't happen inside the database — the refusal rolls its own transaction back, audit row included — so the kit writes it afterwards and rethrows the original error unchanged. Turn it off with `audit: { denials: false }` when a public endpoint behind a guard would write a row per probe.

Audit writes never reject, so a logging failure can't break a request or mask a denial. Pass `audit: { onError }` to find out when one fails.

```ts
const { rows } = await kit.as(principalId).listAuditLogs({
    tenantId,                       // omit for every row you may see, including descendants
    outcome: "denied",
    from: new Date(Date.now() - 86_400_000),
    limit: 100,
});
```

Filters — all optional — are `tenantId`, `actorPrincipalId`, `action`, `targetType`, `targetId`, `requestId`, `outcome`, `from` (inclusive) and `to` (exclusive), plus the usual `limit` and `after`. Rows carry `before` and `after` as JSON, and reading them needs `authz.audit.read` at the tenant; a row with no tenant is a platform-level action and needs that scope at the master tenant.

### Retention

Nothing prunes the log for you, and it grows with every write and every refusal. `kit.pruneAuditLogs` deletes one batch of rows older than a cutoff:

```ts
const cutoff = new Date(Date.now() - 90 * 86_400_000);

for (;;) {
    const { deleted_count, lock_acquired } = await kit.pruneAuditLogs({ before: cutoff });

    if (!lock_acquired) break;      // another replica is already pruning
    if (deleted_count === 0) break; // nothing left older than the cutoff

    await new Promise(r => setTimeout(r, 100));
}
```

It's on `kit`, not on `kit.as(actor)`, because no principal does this — a cron job has none to name. Authority is the database connection, the same basis the other operator tools rest on, so anything that can reach the kit can prune. There's no scope for it and no way to delegate it to a tenant.

**Safe to run on every replica.** An advisory lock means only one prunes at a time, and `lock_acquired: false` tells a replica that didn't get it to stop — which is why the return value isn't just a count, since zero deleted otherwise means both "finished" and "someone else is doing it". Pass `limit` to size the batch (1000 by default) and `tenantId` to prune one tenant's rows, for instance when offboarding.

Two things it won't do: delete its own prune records, so you keep a permanent account of what was removed and when, and write a row when it deleted nothing, so an idle job doesn't fill the table it's meant to drain. `before` is required — a forgotten argument must never mean everything.

### Errors

Database failures are rethrown as typed errors, whichever way the kit connects. Each keeps the code as `sqlState` and the original error as `cause`:

| Class | Code | Meaning |
| --- | --- | --- |
| `AuthzDeniedError` | `P0001` | A rule refused the write. The message doesn't say why, so it can't reveal whether a role or tenant exists |
| `AuthzStateError` | `P0002`, `P0003` | The schema isn't in the expected state. Usually the kit's migrations haven't been applied |
| `AuthzConflictError` | `23505` | The write collided with an existing row |
| `AuthzUsageError` | `23503`, `23514`, `22P02` | A bad ID, a malformed cursor, or an impossible combination of arguments |
| `AuthzConfigError` | `42501`, `PGRST106`, `PGRST202` | The kit is wired up wrongly: the wrong key, `authz` not exposed, or migrations missing. The message says how to fix it |

All five extend `AuthKitError`. Any other error, such as a dropped connection, is rethrown unchanged.

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
| `statusOf(error)` | `{ status, code }` for any kit error, `null` for anything else. `AuthzDeniedError` maps to 403 and other `AuthKitError`s to 500 || `isUuid(value)` | The UUID check the helpers use. Validate any ID with it before it reaches SQL, because a malformed UUID is a database error, which surfaces as a 500 |

`enforceGuard` doesn't handle a missing context itself: when the authentication step didn't run, the binding should throw `MiddlewareNotInstalledError`, with a message explaining how to fix the wiring in that framework. Don't skip the guard when the context is missing, and don't substitute an empty context either. A wiring mistake should be a loud 500, not a quiet 401 or an unguarded route.

## License

MIT
