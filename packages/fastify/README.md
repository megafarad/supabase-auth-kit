# @sirhc77/supabase-auth-kit-fastify

Fastify plugin for [`@sirhc77/supabase-auth-kit`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit). It authenticates requests with Supabase access tokens or API keys, and guards routes by scope at a tenant. Supports Fastify 5.

It checks the `authz` schema that the kit installs into your database, so install the SQL first. See [Install](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit#install) in the main package.

## Install

```bash
npm install @sirhc77/supabase-auth-kit-fastify fastify-plugin @supabase/supabase-js
```

`fastify` (`^5.12.3`) and `fastify-plugin` (`^5.0.0 || ^6.0.0`) are required peer dependencies. Fastify 4 isn't supported: registering the plugin on a Fastify 4 instance fails immediately. The kit reaches your database through a supabase-js client you pass in, or through any Postgres driver you wrap in a query function. The package is ESM-only.

## Quick start

```ts
import Fastify from "fastify";
import { createClient } from "@supabase/supabase-js";
import {
    createFastifyAuthKit,
    getAuthContext,
    tenantFromParam,
} from "@sirhc77/supabase-auth-kit-fastify";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SECRET_KEY!, {
    auth: { persistSession: false, autoRefreshToken: false },
});

const auth = createFastifyAuthKit({
    supabase,
    jwt: {
        jwksUrl: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
        issuer: `${process.env.SUPABASE_URL}/auth/v1`,
    },
    resolveTenant: tenantFromParam("tenantId"),
});

const app = Fastify();

await app.register(auth.plugin);
app.setErrorHandler(auth.errorHandler); // optional; see Errors

app.get(
    "/t/:tenantId/roles",
    { onRequest: auth.requireScope("authz.roles.read") },
    async request => {
        const { principalId } = getAuthContext(request);
        return { principalId };
    },
);
```

`SUPABASE_SECRET_KEY` is your project's **secret key** (`sb_secret_…`, or the legacy `service_role` key). It can act as any principal, so keep it on the server. The client also needs the `authz` schema exposed to the API: locally, add `"authz"` to `schemas` under `[api]` in `supabase/config.toml` and restart the stack; on a hosted project, add it to the exposed schemas in the dashboard's API settings. The kit's migrations already grant the secret key's role what it needs. **Don't grant anything in `authz` to `anon` or `authenticated`**, even though Supabase's guide to exposing a custom schema says to: that would let anyone holding your public key make themselves a platform administrator.

To use a direct Postgres connection instead, pass `query` in place of `supabase`:

```ts
import pg from "pg";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
// ...
    query: (text, params) => pool.query(text, [...params]).then(r => r.rows),
```

`DATABASE_URL` is the connection string for the **`postgres`** role, under *Connect* in the Supabase dashboard; a local stack uses `postgresql://postgres:postgres@127.0.0.1:54322/postgres`. That way needs no exposed schema.

Either connection bypasses row-level security. The kit only ever calls `authz` functions through it, and those functions enforce the rules. Don't write to `authz` tables yourself.

## Options

| Option | |
| --- | --- |
| `supabase` | A supabase-js client holding the secret key. Pass this, `query` or `transport` |
| `query` | `(sql, params) => Promise<Row[]>` on a `postgres` connection. Values must come back as native types (`pg` and `postgres.js` both return them) |
| `transport` | Your own `AuthzTransport`, as exported by the core package |
| `jwt.jwksUrl` | Supabase's JWKS endpoint, `<SUPABASE_URL>/auth/v1/.well-known/jwks.json` |
| `jwt.issuer` | The expected `iss`: `<SUPABASE_URL>/auth/v1`. The issuer isn't checked when you omit it, so set it |
| `jwt.audience` | The expected `aud`. Defaults to `authenticated` |
| `jwt.algorithms` | Defaults to `["ES256", "RS256"]`. Never add `HS256` |
| `jwt.rejectRoles` | Token `role` claims to refuse. Defaults to `["service_role", "anon"]` |
| `verifyBearer` | Your own verifier, `(token) => Promise<authUserId \| null>`, used instead of `jwt`. Use it if you already verify tokens elsewhere, such as at a gateway or with `supabase.auth.getUser` |
| `resolveTenant` | **Required.** Where each request names its tenant. See [Tenant resolution](#tenant-resolution) |
| `apiKeyHeader` | The header carrying an API key. Defaults to `x-api-key` |

Pass exactly one of `supabase`, `query` or `transport`, and either `jwt` or `verifyBearer`. With `jwt`, tokens are verified locally against a cached copy of the key set, so verifying a request doesn't call Supabase Auth.

With `postgres.js`, wrap the client like this: `query: (text, params) => sql.unsafe(text, params as never[])`.

## Credentials

- `Authorization: Bearer <Supabase access token>` for users.
- `x-api-key: <key>` for API keys, as returned once by `createApiKey`.

If a request sends both, the API key is used. A repeated API-key header counts as no key. Authenticating with an API key updates that key's `last_used_at`, which costs one row write per request. That includes public routes, because the plugin authenticates every request in its scope.

## The plugin

`auth.plugin` adds `request.authKit` and an `onRequest` hook that authenticates each request. It's wrapped in `fastify-plugin`, so it covers the context you register it in and every context nested inside that one, not just its own.

The hook **never rejects a request.** A missing or invalid credential simply produces a context with no principal, which lets public routes live alongside guarded ones. The guards are where requests get rejected.

## Guards

```ts
auth.requireScope("invoices.read");
auth.requireAllScopes(["invoices.read", "invoices.write"]);
auth.requireAnyScope(["invoices.read", "authz.audit.read"]);
auth.requireScope("invoices.read", { resolveTenant: tenantFromHeader("x-tenant-id") });
```

Each guard is an async hook for `onRequest`, `preValidation` or `preHandler`. The optional second argument overrides `resolveTenant` for that route only. A guard makes at most one database round trip per tenant per request, however many scopes it checks and however many guards a route stacks.

**Which hook to use.** Use `onRequest` unless the tenant comes from the request body. It rejects a request before the body is parsed. Use `preValidation` or `preHandler` with `tenantFromBody`, because at `onRequest` there is no body yet. Mounting a body-based guard too early is a 400, never an accidental allow.

```ts
app.post(
    "/invites",
    { preHandler: auth.requireScope("authz.bindings.grant", { resolveTenant: tenantFromBody("tenantId") }) },
    handler,
);
```

The guards decide in this order:

| Condition | Status | `code` |
| --- | --- | --- |
| The route is outside the plugin's context, or the plugin isn't registered | 500 | `middleware_missing` |
| No credential was sent | 401 | `unauthenticated` |
| A valid credential that maps to no identity | 403 | `forbidden` |
| No tenant could be resolved, or it isn't a UUID | 400 | `tenant_required` |
| The principal lacks the scope at that tenant | 403 | `forbidden` |

The third row covers someone who signed in with a valid Supabase token but has no authorization identity. The usual cause is registering an address that belonged to a deleted account. That person is authenticated but holds no authority.

Scope checks aren't cached across requests, so a revoked grant takes effect on the next request.

### requireIdentity

`auth.requireIdentity()` requires *somebody*, not a scope: the first three rows of that table, then through. No tenant, no scope, no database round trip.

Use it where the kit's SQL anchors authority on something the request doesn't name — the scope guard can't ask the right question there, and on a route with no tenant it answers 400 to everyone:

```ts
// createWorkspace needs no scope at any tenant: it checks that you are a claimed, active
// principal, creates the tenant under the master and grants you tenant_admin on it.
app.post<{ Body: { name: string } }>(
    "/workspaces",
    { onRequest: auth.requireIdentity() },
    async (request, reply) => {
        const tenantId = await getAuthContext(request).as!.createWorkspace(request.body.name);

        return reply.code(201).send({ tenantId });
    },
);
```

| Write | Authority lives at |
| --- | --- |
| `createWorkspace` | nowhere — any claimed, active principal may create one |
| `revokeBinding` | the binding's own tenant |
| `updateRole`, `addRoleScope`, `removeRoleScope` | the role's tenant |
| `revokeApiKey` | the key's tenant |

Since those routes are refused inside SQL, **install `auth.errorHandler`** so the refusal is a 403 rather than a 500.

**Don't use it on reads.** Reads refuse by filtering, so a caller without the authority gets an empty page instead of an error: `requireIdentity` on a list route answers `200 []` where `requireScope` answers 403. It is also not a faster `requireScope` — on any route where a scope guard can ask the right question, use the scope guard.

## Tenant resolution

Every check asks whether *this principal* holds *this scope* at *this tenant*. The tenant comes from the request:

```ts
tenantFromParam("tenantId");      // request.params.tenantId
tenantFromHeader("x-tenant-id");  // request.headers["x-tenant-id"]
tenantFromQuery("tenant");        // request.query.tenant
tenantFromBody("tenantId");       // request.body.tenantId (use at preValidation or preHandler)
```

Each helper returns nothing unless the value is a well-formed UUID, and the guard answers 400 when it gets nothing. You can pass your own resolver instead, for example one that maps a subdomain to a tenant ID. Resolvers may be async.

Letting the client choose the tenant is safe: a tenant where the caller holds nothing gets the same answer as one that doesn't exist. What you must get right is the order. **Put the guard before the handler**, and never use a tenant ID from the request to scope a query before the guard has run.

## In your handlers

`getAuthContext(request)` returns the request's context. It throws if the plugin's hook didn't run for this request. Use it rather than reading `request.authKit` directly: a check written as `if (request.authKit && …)` silently lets requests through when the plugin is missing.

| Property | |
| --- | --- |
| `principalId` | The principal's ID, or `null` |
| `kind` | `"user"`, `"api_key"`, or `null` |
| `credentialPresented` | Whether the request sent a credential at all |
| `has(tenantId, scope)` | Whether the principal holds a scope. Answered from the same per-request cache the guards use |
| `scopes(tenantId)` | Every scope the principal holds at the tenant |
| `as` | The read and write APIs, acting as this principal. `null` when there's no principal |

### Reads

`as` also lists what the principal is allowed to see, for example to build a tenant switcher or a members page. Without the authority a list comes back empty rather than failing:

```ts
const { rows, nextCursor } = await getAuthContext(request).as!.listTenantBindings(tenantId, { limit: 50 });
```

`getTenant`, `listChildTenants`, `listMyBindings`, `listPrincipalBindings`, `listTenantBindings`, `listRoles`, `listRoleScopes`, `listScopes`, `listApiKeys` and `listAuditLogs` are covered in the [core package's README](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-core#reads), with the scope each one needs and how paging works.

### Writes

`as` runs the kit's write functions with the request's principal already bound as the actor. Every rule is enforced in SQL, so an actor can never grant more than they hold:

```ts
app.post<{ Params: { tenantId: string }; Body: { email: string; roleId: string } }>(
    "/t/:tenantId/invites",
    { onRequest: auth.requireScope("authz.bindings.grant") },
    async (request, reply) => {
        const writes = getAuthContext(request).as!; // the guard already required a principal
        const userId = await writes.inviteUser(request.params.tenantId, request.body.email, request.body.roleId);
        return reply.code(201).send({ userId });
    },
);
```

| Method | |
| --- | --- |
| `grantRole(principalId, roleId, tenantId, expiresAt?)` | Returns the binding ID |
| `inviteUser(tenantId, email, roleId)` | Returns the user ID. Creates an identity if the address has none |
| `revokeBinding(bindingId)` | |
| `createRole(tenantId, name, description, crossesBoundary?)` | Returns the role ID |
| `updateRole(roleId, { name?, description?, crossesBoundary? })` | |
| `addRoleScope(roleId, scopeId)` / `removeRoleScope(roleId, scopeId)` | |
| `createScope(tenantId, name, description?)` | Returns the scope ID |
| `createTenant(parentId, name)` | Returns the tenant ID |
| `createWorkspace(name)` | Returns the tenant ID. The only write with no scope check, so gate it yourself |
| `updateTenant(tenantId, { name?, inherit? })` | |
| `createApiKey(tenantId, label, expiresAt?)` | Returns the plaintext key. It's shown only this once |
| `revokeApiKey(apiKeyId)` | |
| `logAudit(entry)` | Appends an audit row of your own. Never throws |

A refused write throws `AuthzDeniedError`. The message doesn't say why, so it can't reveal whether a role or tenant exists. `AuthzStateError` usually means the kit's migrations haven't been applied, and `AuthzConfigError` means the connection can't reach `authz` at all: the wrong key, or the schema isn't exposed.


### Audit log

Every write records itself, and so does every refusal — a request your guards turn away leaves a row saying who asked for what and why it was refused. Nothing needs calling.

The adapter fills in the request for you, and on Fastify it can be exact: `request.id` is the ID already in your logs (honouring `requestIdHeader`), and the route is the matched **pattern**, so audit rows group by route rather than by every distinct tenant ID. `request.ip` honours `trustProxy`, so set that if you're behind a load balancer.

Supply your own if you'd rather — returning `null` records the rows without any request metadata:

```ts
const auth = createFastifyAuthKit({
    // ...
    requestContext: request => ({ requestId: request.id, method: request.method }),
});
```

Read the trail with `listAuditLogs`, prune it with `auth.kit.pruneAuditLogs` from a scheduled job, and turn refusal logging off with `audit: { denials: false }` if a public endpoint behind a guard would write a row per probe. All three are documented in the [core package's README](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-core#audit-log).
For work outside a request, such as jobs or scripts, `auth.kit` exposes the underlying core API: `hasScope`, `effectiveScopes`, `principalForAuthUser`, `as(principalId)`, and so on.

## Errors

Guard errors need no setup. They carry `status` and `code`, and Fastify's default error handler uses both:

```json
{ "statusCode": 403, "code": "forbidden", "error": "Forbidden", "message": "missing scope invoices.read" }
```

`auth.errorHandler` is optional. It adds handling for write errors: `AuthzDeniedError` becomes a 403, and other `AuthKitError`s become a 500 with code `authz_error`, logged through `request.log`. The response body has the same shape as above. Errors that aren't the kit's are rethrown, so they reach the parent context's error handler unchanged. Install it with `setErrorHandler` in whichever context suits your app.

The error classes are exported if you'd rather handle them yourself: `HttpAuthzError`, `UnauthenticatedError`, `ForbiddenError`, `TenantRequiredError`, `MiddlewareNotInstalledError`, and `statusOf(error)`, which returns the status and code for any kit error.

## License

MIT
