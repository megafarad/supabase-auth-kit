# @sirhc77/supabase-auth-kit

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
