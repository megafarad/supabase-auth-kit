# @sirhc77/supabase-auth-kit-express

Express middleware for [`@sirhc77/supabase-auth-kit`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit). It authenticates requests with Supabase access tokens or API keys, and guards routes by scope at a tenant. Supports Express 4 and 5.

It checks the `authz` schema that the kit installs into your database, so install the SQL first. See [Install](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit#install) in the main package.

## Install

```bash
npm install @sirhc77/supabase-auth-kit-express pg
```

`express` is a peer dependency (`^4.0.0 || ^5.2.1`). `pg` is only an example: the kit works with any Postgres driver you wrap in a query function. The package is ESM-only.

## Quick start

```ts
import express from "express";
import pg from "pg";
import {
    createExpressAuthKit,
    getAuthContext,
    tenantFromParam,
} from "@sirhc77/supabase-auth-kit-express";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const auth = createExpressAuthKit({
    query: (text, params) => pool.query(text, [...params]).then(r => r.rows),
    jwt: {
        jwksUrl: `${process.env.SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
        issuer: `${process.env.SUPABASE_URL}/auth/v1`,
    },
    resolveTenant: tenantFromParam("tenantId"),
});

const app = express();

app.use(auth.authenticate());

app.get("/t/:tenantId/roles", auth.requireScope("authz.roles.read"), async (req, res, next) => {
    try {
        const { principalId } = getAuthContext(req);
        res.json({ principalId });
    } catch (error) {
        next(error);
    }
});

app.use(auth.errorHandler());
```

`DATABASE_URL` is your project's Postgres connection string, for the **`postgres`** role. You'll find it under *Connect* in the Supabase dashboard, and a local stack uses `postgresql://postgres:postgres@127.0.0.1:54322/postgres`. The Supabase service-role key won't work: the `authz` schema is private and can't be reached through the Supabase APIs.

That connection bypasses row-level security. The kit only ever calls `authz` functions through it, and those functions enforce the rules. Don't write to `authz` tables with it yourself.

## Options

| Option | |
| --- | --- |
| `query` | **Required.** `(sql, params) => Promise<Row[]>`. Values must come back as native types (`pg` and `postgres.js` both return them) |
| `jwt.jwksUrl` | Supabase's JWKS endpoint, `<SUPABASE_URL>/auth/v1/.well-known/jwks.json` |
| `jwt.issuer` | The expected `iss`: `<SUPABASE_URL>/auth/v1`. The issuer isn't checked when you omit it, so set it |
| `jwt.audience` | The expected `aud`. Defaults to `authenticated` |
| `jwt.algorithms` | Defaults to `["ES256", "RS256"]`. Never add `HS256` |
| `jwt.rejectRoles` | Token `role` claims to refuse. Defaults to `["service_role", "anon"]` |
| `verifyBearer` | Your own verifier, `(token) => Promise<authUserId \| null>`, used instead of `jwt`. Use it if you already verify tokens elsewhere, such as at a gateway or with `supabase.auth.getUser` |
| `resolveTenant` | **Required.** Where each request names its tenant. See [Tenant resolution](#tenant-resolution) |
| `apiKeyHeader` | The header carrying an API key. Defaults to `x-api-key` |

You must pass either `jwt` or `verifyBearer`. With `jwt`, tokens are verified locally against a cached copy of the key set, so verifying a request doesn't call Supabase Auth.

With `postgres.js`, wrap the client like this: `query: (text, params) => sql.unsafe(text, params as never[])`.

## Credentials

- `Authorization: Bearer <Supabase access token>` for users.
- `x-api-key: <key>` for API keys, as returned once by `createApiKey`.

If a request sends both, the API key is used. A repeated API-key header counts as no key. Authenticating with an API key updates that key's `last_used_at`, which costs one row write per request.

## Guards

```ts
auth.requireScope("invoices.read");
auth.requireAllScopes(["invoices.read", "invoices.write"]);
auth.requireAnyScope(["invoices.read", "authz.audit.read"]);
auth.requireScope("invoices.read", { resolveTenant: tenantFromHeader("x-tenant-id") });
```

Each guard is ordinary middleware. The optional second argument overrides `resolveTenant` for that route only. A guard makes at most one database round trip per tenant per request, however many scopes it checks and however many guards a route stacks.

`authenticate()` **never rejects a request.** A missing or invalid credential simply produces a context with no principal, which lets public routes share the same middleware. The guards are where requests get rejected. They decide in this order:

| Condition | Status | `code` |
| --- | --- | --- |
| The guard is mounted without `authenticate()` in front of it | 500 | `middleware_missing` |
| No credential was sent | 401 | `unauthenticated` |
| A valid credential that maps to no identity | 403 | `forbidden` |
| No tenant could be resolved, or it isn't a UUID | 400 | `tenant_required` |
| The principal lacks the scope at that tenant | 403 | `forbidden` |

The third row covers someone who signed in with a valid Supabase token but has no authorization identity. The usual cause is registering an address that belonged to a deleted account. That person is authenticated but holds no authority.

Scope checks aren't cached across requests, so a revoked grant takes effect on the next request.

## Tenant resolution

Every check asks whether *this principal* holds *this scope* at *this tenant*. The tenant comes from the request:

```ts
tenantFromParam("tenantId");      // req.params.tenantId
tenantFromHeader("x-tenant-id");  // req.headers["x-tenant-id"]
tenantFromQuery("tenant");        // req.query.tenant
tenantFromBody("tenantId");       // req.body.tenantId (needs a body parser in front of the guard)
```

Each helper returns nothing unless the value is a well-formed UUID, and the guard answers 400 when it gets nothing. You can pass your own resolver instead, for example one that maps a subdomain to a tenant ID. Resolvers may be async.

Letting the client choose the tenant is safe: a tenant where the caller holds nothing gets the same answer as one that doesn't exist. What you must get right is the order. **Put the guard before the handler**, and never use a tenant ID from the request to scope a query before the guard has run.

## In your handlers

`getAuthContext(req)` returns the request's context. It throws if `authenticate()` didn't run. Use it rather than reading `req.authKit` directly: a check written as `if (req.authKit && …)` silently lets requests through when the middleware is missing.

| Property | |
| --- | --- |
| `principalId` | The principal's ID, or `null` |
| `kind` | `"user"`, `"api_key"`, or `null` |
| `credentialPresented` | Whether the request sent a credential at all |
| `has(tenantId, scope)` | Whether the principal holds a scope. Answered from the same per-request cache the guards use |
| `scopes(tenantId)` | Every scope the principal holds at the tenant |
| `as` | The write API, acting as this principal. `null` when there's no principal |

### Writes

`as` runs the kit's write functions with the request's principal already bound as the actor. Every rule is enforced in SQL, so an actor can never grant more than they hold:

```ts
app.post(
    "/t/:tenantId/invites",
    express.json(),
    auth.requireScope("authz.bindings.grant"),
    async (req, res, next) => {
        try {
            const writes = getAuthContext(req).as!; // the guard already required a principal
            const tenantId = req.params.tenantId as string;
            const userId = await writes.inviteUser(tenantId, req.body.email, req.body.roleId);
            res.status(201).json({ userId });
        } catch (error) {
            next(error);
        }
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

A refused write throws `AuthzDeniedError`. The message doesn't say why, so it can't reveal whether a role or tenant exists. `AuthzStateError` usually means the kit's migrations haven't been applied.

For work outside a request, such as jobs or scripts, `auth.kit` exposes the underlying core API: `hasScope`, `effectiveScopes`, `principalForAuthUser`, `as(principalId)`, and so on.

## Errors

Guard errors carry `status` and `code`, so Express's default handler already responds with the right status. `auth.errorHandler()` is optional: it renders the kit's errors as JSON and passes anything else to your next error handler unchanged.

```json
{ "error": "forbidden", "message": "missing scope invoices.read" }
```

It also maps write errors: `AuthzDeniedError` becomes a 403, and other `AuthKitError`s become a 500 with code `authz_error`. The error classes are exported if you'd rather handle them yourself: `HttpAuthzError`, `UnauthenticatedError`, `ForbiddenError`, `TenantRequiredError`, `MiddlewareNotInstalledError`, and `statusOf(error)`, which returns the status and code for any kit error.

## Express 4

The kit's own middleware forwards errors correctly on both major versions. Your async handlers are another matter: Express 4 doesn't catch a rejected promise, so a handler that throws hangs the request. On Express 4, catch errors in your own async handlers and pass them to `next`, as the examples above do.

## Types

The package adds `authKit?: AuthzContext` to Express's `Request`. It's named `authKit` so it doesn't collide with `req.auth` from `express-jwt` or `express-oauth2-jwt-bearer`.

## License

MIT
