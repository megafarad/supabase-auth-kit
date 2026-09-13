# `@sirhc77/supabase-auth-kit-core` (packages/core)

The framework-agnostic half of the kit. `packages/express` and `packages/fastify` are thin bindings over it; **nothing here may import Express or Fastify**, and that constraint is what keeps the second adapter cheap.

## Package shape

- `jose` is the only runtime dependency in the repo. It is declared here deliberately: `jose` also appears in `node_modules` as a transitive of the `supabase` CLI devDependency, so relying on that would work locally and break for every consumer.
- ESM only, `module: NodeNext`, `strict: true`, `declaration: true`, `src/` → `dist/`, `files` ships `dist`. `"types": ["node"]` is required — jose's remote JWKS uses global `fetch`.
- Tests live in `test/`, outside the tsconfig's `include: ["src"]`, so they never reach `dist`. The integration suites share `test/integration/stack.ts` and run once per transport (`describe.each(TRANSPORTS)`); the supabase-js case needs the API on :54321 with `authz` exposed, and skips without it. `@supabase/supabase-js` is a root devDependency for those tests only — core must never import it.

## The database seam: transports

Core never builds SQL above `transport.ts`. Everything calls an `AuthzTransport` **by function name, with arguments keyed by their SQL parameter names** (`p_actor_principal_id`, …):

| Transport | Reaches the database as | Option |
| --- | --- | --- |
| `fromQuery(queryFn)` | the `postgres` owner, on a direct connection. Builds `select authz.fn(p_x => $1, …)` — Postgres named notation, so both transports share one argument contract | `query` |
| `fromSupabase(client)` | `service_role`, through PostgREST: `client.schema('authz').rpc(fn, args)` with the secret key. Needs `authz` in the project's exposed schemas | `supabase` |

`createAuthKit` takes exactly one of `query`, `supabase` or `transport`, as optional fields on one interface rather than a union — the Express and Fastify option types `extends` it.

Rules the two must keep, because nothing above them can tell which is in use:

- **Only names from `AUTHZ_FUNCTIONS` are called**, and that list is the `service_role` grant list — `privileges.integration.test.ts` holds them equal. `fromQuery` interpolates names into SQL text, so it also checks every function and argument name against a strict identifier pattern; values only ever travel as bind parameters.
- **Same value shapes.** JSON can only carry strings, so `fromQuery` turns `Date`s into ISO strings, and writes serialise `Date` arguments themselves. `undefined` arguments are omitted (the SQL default applies); `null` is passed.
- **Same errors.** supabase-js *resolves* with `{ error }`; `fromSupabase` re-raises it as an `Error` carrying PostgREST's `code`, the shape `pg` throws. `createAuthKit` wraps whichever transport in `rethrowAsAuthKitError` once, so checks, reads and writes all surface typed errors.
- **`SupabaseRpcClient` is typed loosely on purpose** (`schema(schema: never): unknown`). A client created with generated types narrows `schema()` to the schemas in those types, which do not include `authz`, so any precise signature rejects it and forces every typed app to cast. The precise shape lives privately in `fromSupabase`.

Neither connection is subject to RLS (the owner bypasses it; `service_role` has `BYPASSRLS`), so the `SECURITY DEFINER` functions are the only enforcement, and core issues nothing but calls to them.

Values must come back as native types. `hasScope` treats anything that is not `true` as false, so a driver that stringified booleans would fail closed but silently deny.

## What is fail-closed, and how

- `hasScope` and `effectiveScopes` short-circuit a null principal or tenant to `false` / `[]` **without querying**. This is an optimisation of the answer SQL already gives, not a second rule: `has_scope(null, …)` is also false. An integration test asserts the two agree, so the short circuit cannot start hiding a divergence.
- The unit tests assert both halves: that the answer is `false`, *and* that the query stub was never called. The second is what proves the branch is deliberate rather than an accident of an empty result set.
- `resolvePrincipal` keeps `credentialPresented` separate from `principalId` because the two nulls are different questions. No credential is "who are you" (401); a credential that verified but maps to no principal is authenticated-with-zero-authority (403). Collapsing them loses the distinction the model doc raises as open question 1.

## JWT verification

Local and asymmetric. Supabase issues **ES256 via JWKS** — confirmed against a live stack, whose `/auth/v1/.well-known/jwks.json` serves one EC/P-256 key — so this is not the legacy HS256 shared secret.

- `algorithms` defaults to `['ES256','RS256']` and **must never include HS256**. A JWKS publishes public keys; accepting a symmetric algorithm lets an attacker MAC a token with a public key's raw bytes. jose would refuse to derive a symmetric key from a JWKS anyway, but the pin states the intent where someone might widen it.
- `rejectRoles` defaults to `['service_role','anon']`. Supabase's own API keys are JWTs and get pasted into Authorization headers.
- The `sub` claim is validated as a UUID **before** it reaches Postgres. Otherwise a malformed subject is a `22P02` cast error — a 500 for what is really a bad credential.
- A rejected token is a `null`. A JWKS outage is **not**: infrastructure failures are rethrown, because folding them into null would turn an outage into a wall of 401s that reads as a client problem.
- `createRemoteJWKSet` is built once at factory time, never per request — that object *is* the key cache.
- `verifyBearer` can be supplied directly instead of `jwt`, for apps that already verify tokens (`supabase.auth.getUser`, a gateway) and should not do it twice.

## Writes and reads

`kit.as(principalId)` returns `ActorApi` — the thirteen mutating functions (`writes.ts`) and the read functions (`reads.ts`), all with the actor pre-bound. Binding it is the point: the SQL takes the actor as its first argument precisely so nothing reads the JWT, and a caller who threads it by hand will eventually thread the wrong one. Nothing here re-checks authority — a check in TypeScript would be a second opinion that can disagree with the enforcing one.

Reads return `Page<T>` (`{ rows, nextCursor }`) over the keyset paging in SQL. Rows are `snake_case`, as everywhere, with `page_cursor` stripped. Two things are done in TypeScript as well as SQL, deliberately:

- **The limit clamp** ([1, 1000], default 100), so a full page is recognised as full and a fractional limit is not a cast error.
- **Cursor validation.** SQL compares the sort key before the id half, so a garbage cursor usually filters silently instead of failing the uuid cast. Checking the 36-character id prefix up front turns it into an `AuthzUsageError`.

Errors are typed by SQLSTATE. Every guard in SQL raises bare, so all of them arrive as `P0001` and map to `AuthzDeniedError` — which is the honest reading from a caller's side and has the useful property of not leaking whether a role or tenant exists. `P0002`/`P0003` (a `select … into strict` that found nothing) map to `AuthzStateError`, usually meaning the bootstrap migration has not run. `42501`, `PGRST106` and `PGRST202` are wiring — permission denied, schema not exposed, function unknown to PostgREST — and map to `AuthzConfigError` with the fix appended to the message; they are deliberately not `AuthzDeniedError`, because a misconfigured deployment answering 403 to everyone reads as a caller problem. Finer classification of the `P0001` group would need `using errcode = …` on those 34 raise sites; adding it later only changes the table in `errors.ts`.

## HTTP layer shared by the adapters

Everything a binding needs that is not framework-shaped lives here, so the security-critical parts exist once. None of it imports a framework — requests are typed structurally.

| Module | Provides |
| --- | --- |
| `guard.ts` | `enforceGuard(context, resolveTenant, check)` — **the** decision order (401 / 403 / 400 / check), and the `checkScope` / `checkAllScopes` / `checkAnyScope` builders |
| `context.ts` | `AuthzContext` and `createAuthzContext(kit, resolved)` — the per-request scope memo (promises, not values, so concurrent checks coalesce) and the pre-bound `as` |
| `http-errors.ts` | `HttpAuthzError` and subclasses, `statusOf`. `status` is what both Express's `finalhandler` and Fastify's default handler read |
| `headers.ts` | `credentialsFromHeaders(headers, apiKeyHeader)` — Bearer only, and an array-valued API-key header is no key |
| `tenant.ts` | `tenantFromParam/Header/Query/Body` over a structural `TenantSource`, and the generic `TenantResolver<R>` each binding narrows |

A missing context is the one guard branch left to the binding, because the fix its error names (mount a middleware, register a plugin) is framework-specific — hence `MiddlewareNotInstalledError`'s message parameter. `test/guard.test.ts` pins the order here; each adapter's suite pins it again end to end.

## Deliberate non-features

- **No cross-request scope cache.** `revoke_binding` is a security operation; caching scopes across requests turns revocation into an eventual-consistency problem. Memoization is per request only, and lives in the framework binding.
- **No traversal in TypeScript.** `authz.has_scope` and `authz.tenant_chain` own the ancestor walk, the `inherit = false` filter and the `crosses_boundary` exemption.
