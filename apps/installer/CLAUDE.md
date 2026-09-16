# `@sirhc77/supabase-auth-kit` (apps/installer)

The published core package. It ships the SQL and a `supabase-auth-kit` bin, and has **no library entry point** — `bin/install-migrations.ts` compiles to `dist/install-migrations.js` and that is the whole surface.

The authorization model the SQL encodes lives in `supabase/CLAUDE.md`. This file covers the pipeline that produces the migrations and the installer that delivers them.

## Local Supabase stack

Config lives in `supabase/config.toml`, project id `supabase-auth-kit`. It adds `authz` to `[api] schemas`, which the supabase-js transport needs; changing `[api]` takes a `supabase stop` and `start`, not just a reset. The CLI looks for `./supabase`, so **run these from `apps/installer`** (or pass `--workdir apps/installer`) — from the repo root it will not find the project.

The stack binds fixed ports, and **another local Supabase project can already hold them.** `supabase start` then fails, while `supabase status` and the integration suites happily talk to the *other* project's database on :54322. Check `docker ps` for `supabase_db_supabase-auth-kit` before trusting a test run.

```bash
npx supabase start          # API 54321, DB 54322, Studio 54323, Inbucket 54324
npx supabase db diff -f <name>   # generate a migration from the declarative schemas
npx supabase db reset       # rebuild local DB from migrations + seed
```

## Migration pipeline (the central mechanism)

Migrations are **generated, never hand-written** — with two deliberate kinds of exception, each for a different reason: the bootstrap migration at step 3 (data) and the privileges migrations (grants). Both are cases `db diff` structurally cannot see.

1. `supabase/schemas/*.sql` is the declarative source of truth (`000_auth_kit_tables.sql`, `001_auth_kit_functions.sql`, `002_auth_kit_policies.sql`). Edit these. **Everything the kit creates gets declared here, including `on_auth_user_confirmed` on `auth.users`.** `db diff` builds its shadow from the same Supabase base image, so `auth` objects are compared like any others — an object created only in migration history and never declared reappears in every later diff as a `drop`. Declaring it is what makes repeated diffs idempotent; it does not put the rest of the `auth` schema at risk, since the shadow and the local database start from the same base.
2. `supabase db diff` turns schema changes into timestamped files in `supabase/migrations/`. 20 exist so far, from `20260907055016_auth_kit.sql` (the whole schema) through `20260913040000_auth_kit_rpc_privileges.sql`; each later one is an incremental diff, so they are applied in filename order and never edited after the fact. After generating one, `npx supabase db diff` with no `-f` should report `No schema changes found`.
3. `20260907060000_auth_kit_bootstrap.sql` is the first hand-written exception. `db diff` compares structure and not data, so the rows the model requires cannot come from `schemas/` — **do not try to regenerate it**, and keep it sorting after the schema migration so the tables exist first. It is idempotent (`ON CONFLICT DO NOTHING` throughout) and resolves the master tenant rather than assuming it, so it is safe against a database that already has a root tenant.

   `20260909060000_auth_kit_privileges.sql` is the second, because **migra does not diff privileges at all**. Verified: with the revokes declared in `schemas/` and absent from the database, `db diff` reported `No schema changes found` while every function in the schema still had `PUBLIC EXECUTE`. Grants therefore cannot live in `schemas/` — a declarative file there would never reach a migration. The same blindness makes the hand-written form stable: later diffs will not undo it.

   `20260913040000_auth_kit_rpc_privileges.sql` is the second privileges migration. It makes `authz` callable through PostgREST by `service_role` and nobody else: `USAGE` on the schema, `EXECUTE` on exactly the functions core calls, and it revokes the default privilege the first one set. See the model doc's access posture.

   **Changing a function's signature is a drop and a create, and it takes the grants with it.** Overloading is forbidden — PostgREST passes arguments by name and cannot tell overloads apart — so adding a parameter cannot be a `create or replace`. `db diff` emits `drop function` + `create function`, and a dropped function loses every `GRANT` made against it, including `service_role`'s. The accompanying privileges migration must therefore **re-grant every function it touched**, not only the new ones; `privileges.integration.test.ts` catches the omission by holding `service_role`'s set equal to `AUTHZ_FUNCTIONS`. `20260916…_auth_kit_audit_privileges.sql` is the worked example: adding `p_request_ctx` to the 13 writes meant re-granting all 13.

   **Any migration that adds a function to `authz` must, by hand:**
   - repeat the bulk `revoke execute on all functions in schema "authz" from public`. No `ALTER DEFAULT PRIVILEGES` form prevents a new function from getting the built-in `PUBLIC EXECUTE` — see `20260909060000`'s own comment for the three ways that was verified;
   - if core will call it, `grant execute on function … to "service_role"` explicitly **and** add it to `AUTHZ_FUNCTIONS` in `packages/core/src/transport.ts`. Nothing is granted by default any more, so a function missing the grant fails on the supabase-js transport with a permission error.

   `packages/core/test/integration/privileges.integration.test.ts` enforces all of it: no `PUBLIC EXECUTE`, nothing for `anon`/`authenticated`, `service_role`'s set equal to `AUTHZ_FUNCTIONS`, no default privileges, no overloads.
4. `bin/install-migrations.ts` is the consumer-facing installer. `npx supabase-auth-kit` in a downstream project copies every `.sql` from the package's `supabase/migrations/` into the consumer's `./supabase/migrations/`, renaming each to `<version>_supabase_auth_<original>.sql`. `<version>` is Supabase's own 14-digit UTC `YYYYMMDDHHMMSS`, starting at the current second or one second past the newest version already in the directory, whichever is later, and advancing a second per file — so the copies sort after the consumer's existing migrations and keep their relative order. **Don't go back to `Date.now()`**: its 13 digits sort *before* every 14-digit version, lexically and numerically, and `supabase db push` then refuses the copies as inserted before the last applied migration. It skips anything already installed — the original filename is recoverable from that `_supabase_auth_` marker — so re-running is a no-op while an upgrade still picks up migrations a newer version added. It ends by printing how to expose `authz` for the supabase-js transport, and the warning never to grant `anon` or `authenticated` anything there — the one step of setup a migration cannot do.

## Packaging

`package.json` `files` ships `dist` and `supabase/migrations` only. The installer resolves its source dir as `../supabase/migrations` relative to the compiled `dist/install-migrations.js`, so the local dev `config.toml` and the declarative `schemas/` stay out of the tarball. `npm pack` produces `dist/install-migrations.js`, `package.json`, and the generated migrations.

`tsconfig.json` compiles `bin/` → `dist/` with `rootDir: bin`, and pins `include`/`exclude` — without them `tsc` picks up previously emitted output and nests a stale `dist/`. Unlike the adapter packages it does not set `declaration: true`; there are no types to publish.
