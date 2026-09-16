# @sirhc77/supabase-auth-kit

## 0.3.0

### Minor Changes

- 6d59413: Write and read the audit log.
  
  `authz.audit_logs` has existed since the first migration with indexes, an RLS policy and an `authz.audit.read` scope, but nothing wrote to it and nothing read it. Both halves now exist.
  
  - **Writes log themselves.** All thirteen mutating functions record what they did — actor, tenant, target, `before`/`after` — inside the same transaction as the change, so the log cannot describe a change that rolled back. Nothing needs calling.
  - **Refusals are recorded too**, with `outcome: "denied"` and the refusal's message in `reason`. A denial cannot log itself: `raise exception` rolls back the audit row with everything else, so the kit writes it afterwards and rethrows the original error unchanged. Both a refused write and a request a scope guard turns away leave a row. Turn it off with `audit: { denials: false }`; `audit: { onError }` reports a failed audit write, which otherwise never surfaces, because audit writes never reject.
  - **Read API.** `listAuditLogs(filter?)` on `kit.as(principalId)`, newest first, filtered to rows at tenants where the actor holds `authz.audit.read` — and, for platform-level rows with no tenant, that scope at the master. Filters: `tenantId`, `actorPrincipalId`, `action`, `targetType`, `targetId`, `requestId`, `outcome`, `from`, `to`. Omitting `tenantId` returns every row you may see, descendants included.
  - **Request context.** `kit.as(principalId, requestContext)` binds the request alongside the actor, and every audit row carries it. The Express and Fastify adapters fill it in automatically and expose a `requestContext` option to replace or suppress it. Fastify records the matched route pattern and Fastify's own request id; Express records the URL and honours `x-request-id`, generating one otherwise.
  - **`logAudit(entry)`** appends a row of your own — an application event, or a refusal your own code decided.
  - **Retention.** `kit.pruneAuditLogs({ before, tenantId?, limit? })` deletes one batch of rows older than a cutoff, and is safe to run on every replica of a service: an advisory lock single-flights it, and the `{ deleted_count, lock_acquired }` result tells a replica that didn't get the lock apart from one that found nothing left. It's on the kit rather than `kit.as(actor)` because no principal does this — the SQL function takes no actor and checks no scope, so authority is the connection, as it is for the other operator tools. It never prunes its own prune records, and never logs a run that deleted nothing.
  
  **Schema changes.** `audit_logs.request_id`, `method` and `route` are now nullable, so a caller with no HTTP request (a job, a migration) can still log; new `outcome` and `reason` columns carry refusals. `audit_logs.updated_at` is **dropped** — the table is append-only, so it only ever equalled `created_at` while implying rows here get amended. Nothing had ever written to this table, so no deployed copy of it has rows to lose. The thirteen write functions take a new trailing `p_request_ctx jsonb` argument — additive for callers going through this package, but a **drop and recreate** in SQL, since `authz` forbids overloads. A new privileges migration re-grants `service_role` `EXECUTE` on all thirteen plus `log_audit` and `list_audit_logs`; apply the migrations before deploying.

## 0.2.0

### Minor Changes

- b78de4c: Connect with supabase-js, and read through the kit.
  
  - **supabase-js transport.** Pass `supabase: createClient(url, secretKey)` instead of a `query` function. It needs `authz` added to your project's exposed API schemas; the installer prints how. A direct Postgres `query` function still works and needs no exposed schema. Custom transports are supported through `transport`, with `fromSupabase` and `fromQuery` exported.
  - **Read API.** `kit.as(principalId)` (and `as` on the request context) now also has `getTenant`, `listChildTenants`, `listMyBindings`, `listPrincipalBindings`, `listTenantBindings`, `listRoles`, `listRoleScopes`, `listScopes` and `listApiKeys`. Each is backed by a new `authz` SQL function, filtered to what the actor may see, and paged by cursor.
  - **Privileges.** A new migration grants `service_role` `USAGE` on `authz` and `EXECUTE` on exactly the functions the adapters call. It also **revokes** `service_role`'s `EXECUTE` on everything else, including `provision_admin`, `reclaim_identity` and the internal helpers, and removes the default privilege that granted it new functions automatically. Run operator tools from the SQL editor as `postgres`, as before.
  - **Errors.** New `AuthzConfigError` for wiring failures (`42501`, `PGRST106`, `PGRST202`), with the fix in the message. `22P02` now maps to `AuthzUsageError`. Checks and identity lookups now raise typed errors too, not only writes.
  - **Custom `query` stubs:** `effective_scopes` is now read as `select * from authz.effective_scopes(...)`, so a stub must return rows with a `scope_name` column rather than `result`.

## 0.1.1

### Patch Changes

- e46ff7e: Publish with npm provenance. Each package now declares `publishConfig.provenance` and the
  `repository` field that provenance generation requires, so releases built by GitHub Actions carry
  a verifiable link back to the commit and workflow that produced them.
