# `@sirhc77/supabase-auth-kit-express` (packages/express)

Express binding over `@sirhc77/supabase-auth-kit-core`. Thin by design: every authorization decision, JWT verification and database call lives in core, and so do the guard's decision order (`enforceGuard`), the per-request context and its memo (`createAuthzContext`), the HTTP errors and `statusOf`, header parsing and the tenant helpers — shared with `packages/fastify`, re-exported here unchanged. Nothing framework-agnostic belongs here; what remains is `getAuthContext`, the `declare global` block, `wrapAsync` and the error middleware.

## Package shape

- `express` is a **peer dependency** (`^4.0.0 || ^5.2.1`) and a devDependency for typechecking. Never a runtime dependency — the consumer owns the Express instance.
- `express4` is an aliased devDependency (`npm:express@^4.21.2`). The guard suite runs parameterised over **both real versions**, which is the only way to actually test the advertised peer range.
- ESM only, `module: NodeNext`, `strict: true`, `declaration: true`, `src/` → `dist/`, `files` ships `dist`.

## Usage

```ts
const auth = createExpressAuthKit({
    supabase,                                  // secret-key client; or query: (sql, params) => Promise<Row[]>
    jwt: { jwksUrl: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json` },
    resolveTenant: tenantFromParam("tenantId"),
});

app.use(auth.authenticate());
app.get("/t/:tenantId/roles", auth.requireScope("authz.roles.read"), handler);
app.use(auth.errorHandler());                  // opt-in
```

## The four rules from the model, as they land here

- **The connection bypasses RLS.** The policies in `002_auth_kit_policies.sql` are dormant under posture A and will not catch a mistake here; the `SECURITY DEFINER` functions are the enforcement path. The connection is either the **`postgres` owner** connection string (`query`) or a supabase-js client holding the **secret key** (`supabase`) — see the transports in `packages/core/CLAUDE.md`. Options pass straight through to core's `createAuthKit`, so this package has no opinion on which.
- **Resolve the actor, then pass it explicitly.** `req.authKit.as` is the read and write API with this request's principal pre-bound, and it is `null` when there is no principal — so the type system carries the rule that you must be somebody before you can read or write.
- **No identity is zero scopes.** See below; this is the crux.
- **Authorization is per (principal, tenant, scope)**, and scope names are SQL identifiers used verbatim.

## `authenticate()` never rejects

A missing or bad credential yields a context with no principal and the request proceeds. That reads like a fall-open until you see why it isn't: an absent principal carries zero scopes, and the **guard** is the enforcement point. Keeping rejection out of the middleware is what makes 401 and 403 distinguishable at the guard, and lets a public route sit behind the same `app.use`.

`requireScope` decides in a fixed order — core's `enforceGuard`, shared with Fastify — and every branch either denies or continues; none skips:

| Condition | Result |
| --- | --- |
| no context (guard mounted without `authenticate()`) | **500** `middleware_missing` — a wiring bug is never an allow |
| no principal, no credential presented | **401** `unauthenticated` |
| no principal, credential presented | **403** `forbidden` |
| tenant unresolvable or not a UUID | **400** `tenant_required` |
| principal lacks the scope | **403** `forbidden` |

The second 403 is open question 1 made concrete: a token that verified against the project's own JWKS but maps to no `authz.users` row — reachable by registering an address a retired identity still holds. It is a clean 403, **never a 500**, and there is a test on both Express versions asserting the downstream handler did not run.

`getAuthContext(req)` throws rather than returning undefined, because the shape to make unwritable is `if (req.authKit && !(await req.authKit.has(t, s))) deny()` — which silently allows when the middleware is missing. Guards use the accessor, never optional chaining.

`req.authKit` is named that, not `req.auth`, to avoid a hard compile error for consumers who also use express-jwt or express-oauth2-jwt-bearer — both merge `Request.auth`. The `declare global` block lives in `src/index.ts` rather than a side file, so it cannot be dropped by `.d.ts` import elision.

## Scopes are memoized per request, per tenant

`has()` answers from a memoized `effective_scopes` set rather than calling `has_scope` per check. The two are equivalent by construction — `has_scope` is an EXISTS over `effective_scopes`, the same traversal at the same cost — so fetching the set is strictly more information per round trip and turns N checks into one query. `requireAllScopes`/`requireAnyScope` cost one round trip regardless of how many scopes are listed.

The **promise** is cached, not the resolved value, so concurrent checks in one tick coalesce into a single query. The memo is per request only; see `packages/core/CLAUDE.md` for why there is no cross-request cache.

## Express 4 vs 5

Express 5 awaits a handler and forwards rejections; Express 4 does not — there, an unhandled rejection **hangs the request** and can take the process down, so it is an availability bug rather than a wrong status. `wrapAsync` in `src/async.ts` never relies on the framework:

- The returned handler is **synchronous**. An `async` outer returns a promise v5's router would also await, creating two paths to `next(err)` and divergent behaviour between versions.
- `next` is latched, so a handler that calls `next()` and then throws cannot call it twice after a response is in flight.

Errors go to `next(err)`; `errorHandler()` is opt-in and re-delegates anything that is not ours. This package never registers a route, which is why the dual peer range is cheap — every v5 breaking change that bites libraries is on the route-registration side.

## Tenant resolution

`resolveTenant` is required, because every check is per (principal, tenant, scope) and where the tenant lives is app-specific. Helpers: `tenantFromParam`, `tenantFromHeader`, `tenantFromQuery`, `tenantFromBody` — from core, typed over a structural request, so they slot into this package's `TenantResolver` (`CoreTenantResolver<Request>`) unchanged.

Every helper validates UUID shape and returns `undefined` when absent or malformed. That is not hygiene: an arbitrary string reaching `has_scope` makes Postgres raise `22P02`, which would surface as a 500 for what is really a bad request. Letting the client name the tenant is safe — `has_scope` is the check, and a tenant you hold nothing at answers identically to one that does not exist, so there is no enumeration oracle. The consumer's obligation is **ordering**: guard first, then handler, and never scope a query on a resolved tenant before the guard has run.

## Request context for audit rows

`authenticate()` builds a `RequestContext` and passes it to `createAuthzContext`, which binds it alongside the actor so every audit row a request writes carries it. `requestContextFromExpress` is the default and is exported; the `requestContext` option replaces it, and returning `null` records rows with no request metadata.

Express gives less than Fastify here, in two ways the default cannot fix and that are stated in its doc comment rather than hidden:

- **The route is the URL, not the pattern.** `req.route` is not populated until Express has matched a route, and `authenticate()` runs as application-level middleware *before* that, so `req.originalUrl` is the honest answer. A consumer who wants `/t/:tenantId/x` has to supply it.
- **The request id is minted unless a header carries one.** There is no `req.id`; `x-request-id` is honoured, and a uuid is generated otherwise. A minted id still correlates one request's rows with each other.

`req.ip` honours `trust proxy`, so a deployment behind a load balancer that has not set it records the balancer's address.

The denial rows themselves come from the core's `enforceGuard` — see `packages/core/CLAUDE.md` — so both adapters record the same two 403 branches and neither records the 401.

## Known consideration

When a request carries both an API key and a bearer token, the API key wins (core's `resolvePrincipal`). An alternative is to reject the request outright, on the grounds that silent precedence lets a caller steer which identity the server uses by adding a header. Precedence was kept because rejecting would break clients that legitimately send both; revisit if that trade stops holding.
