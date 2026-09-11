# `@sirhc77/supabase-auth-kit-fastify` (packages/fastify)

Fastify binding over `@sirhc77/supabase-auth-kit-core`. Thin by design, like the Express adapter: the guard's decision order, the per-request scope memo, the HTTP errors, header parsing and the tenant helpers all live in core (`packages/core/CLAUDE.md`, "HTTP layer shared by the adapters"). What is here is only what is Fastify-shaped: the plugin, the request decorator, the hooks and the error handler.

## Package shape

- `fastify` (`^5.12.3`) and `fastify-plugin` (`^5.0.0 || ^6.0.0`) are **required peer dependencies** — `peerDependenciesMeta` marks both `optional: false` — and devDependencies for local typechecking. Never make either a runtime dependency; the consumer owns the Fastify instance.
- **Fastify 4 is deliberately unsupported**: it is end-of-life, and carried unpatched high-severity advisories. The plugin declares `fastify: "5.x"`, which Fastify itself enforces at `register` time, so a v4 instance fails loudly rather than half-working. With a single major in range there is no aliased second version to test against — unlike Express's `express4`.
- `fastify-plugin` 5 and 6 are both Fastify 5 lines with byte-identical runtime code (5.x only names its entry `plugin.js`), and the emitted `.d.ts` references none of its types, so the suite runs on the 6.x devDependency alone. Re-check that before widening the range again.
- ESM only, `module: NodeNext`, `strict: true`, `declaration: true`, `types: ["node"]` (for `node:http` `STATUS_CODES`), `src/` → `dist/`, `files` ships `dist`.

## Usage

```ts
const auth = createFastifyAuthKit({
    query,                                     // BYO: (sql, params) => Promise<Row[]>
    jwt: { jwksUrl: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json` },
    resolveTenant: tenantFromParam("tenantId"),
});

await app.register(auth.plugin);
app.get("/t/:tenantId/roles", { onRequest: auth.requireScope("authz.roles.read") }, handler);
app.setErrorHandler(auth.errorHandler);        // opt-in; see below
```

A factory rather than an options plugin with an instance decorator: the guards exist before `register` resolves, there is no `FastifyInstance` augmentation, and no `app.authKit` to confuse with `request.authKit`.

## The plugin

`auth.plugin` is wrapped in `fastify-plugin` — without it the decorator and hook would cover only the plugin's own encapsulation context and the consumer's routes would see nothing. The test that allows a request on a root-level route is also the proof of this: replacing `fp` with a bare function turns it into a 500.

It decorates `request.authKit` with `null` (Fastify 5 accepts only `null` or a getter for a reference-type request decorator) and adds an **instance-level `onRequest` hook** that resolves credentials and attaches the context. Instance hooks run before route hooks of the same stage, so a guard sees the context whichever stage it is mounted at. Like Express's `authenticate()`, the hook **never rejects** — a missing or bad credential yields a context with no principal, and the guard decides.

`getAuthContext(request)` throws `MiddlewareNotInstalledError` for both `undefined` (the decorator is absent from this context) and `null` (the hook did not run). Both are the same wiring bug, and both are a 500 — including a route outside the context the plugin was registered in, which has its own test.

## Guards

`requireScope`, `requireAllScopes` and `requireAnyScope` return an async hook usable at `onRequest`, `preValidation` or `preHandler`. They run the core's `enforceGuard`, so the table in `packages/express/CLAUDE.md` holds here verbatim — 500 / 401 / 403 / 400 / 403 — and the open-question-1 case (verified token, no authz identity) is a clean **403, never a 500**, tested with the handler asserted not to have run.

No `wrapAsync` equivalent is needed: Fastify awaits async hooks and routes a rejection to the error handler.

**Which stage.** `onRequest` is the default recommendation — it rejects before the body is parsed. Use `preValidation` or `preHandler` only when the tenant comes from the body (`tenantFromBody`). At `onRequest` there is no body yet, so `tenantFromBody` yields nothing and the guard answers 400: early is a fail-closed mistake, never an allow.

## Errors

Guard errors need no setup. They carry `status` and `code`, which Fastify's default error handler honours, so a denial renders as `403 {"statusCode":403,"code":"forbidden","error":"Forbidden","message":…}`.

`auth.errorHandler` is opt-in and adds only the core's write-API errors: `AuthzDeniedError` becomes a 403 and other `AuthKitError`s a logged 500, in the same body shape as the default handler, so installing it never changes how a guard error looks. Anything that is not ours is **rethrown**, not replied to — Fastify hands a throw from an error handler to the parent context's handler, so the consumer's own handling still sees it. Pass it to `setErrorHandler` wherever that suits the app's encapsulation.

## The four rules from the model, as they land here

- **The connection bypasses RLS.** It is the `postgres` owner connection string (`service_role` is `NOLOGIN` in Supabase); the `SECURITY DEFINER` functions are the enforcement path and the RLS policies are dormant defence in depth.
- **Resolve the actor, then pass it explicitly.** `request.authKit.as` is the write API with the request's principal pre-bound, and `null` without one.
- **No identity is zero scopes.** See the guard section; the SQL is already fail-closed and the adapter must not turn the null into a 500 or skip the check.
- **Authorization is per (principal, tenant, scope)**, scope names are SQL identifiers used verbatim, and the traversal lives only in SQL.

`verify_api_key` writes `last_used_at`, and the hook runs for every request in the plugin's context — public routes included — so API-key auth costs one row write per request. Core's `resolvePrincipal` guarantees it is never more than one.
