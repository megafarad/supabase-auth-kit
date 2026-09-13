# supabase-auth-kit

Embedded authorization for Supabase: hierarchical multi-tenancy, roles and scopes, and API keys, implemented in SQL inside your own Supabase Postgres database, with middleware for Express and Fastify.

Supabase handles authentication. This kit decides what an authenticated user, or an API key, is allowed to do, and at which tenant:

- **Tenants form a tree** under a single master tenant. Your customers' workspaces are its children, and they can have sub-tenants of their own.
- **Roles bundle scopes, and bindings grant roles.** A binding gives a user or an API key one role at one tenant, and it applies at every tenant below that one.
- **Tenants can cut themselves off** from what's defined above them with `inherit = false`. Roles marked `crosses_boundary` still reach through the cut, so the platform operator is never locked out.
- **The rules live in SQL.** `authz.has_scope(principal, tenant, scope)` answers every check, and SQL functions guard every write, so the rules hold for any server that calls them.

## Packages

| Package | |
| --- | --- |
| [`@sirhc77/supabase-auth-kit`](apps/installer) | The `authz` schema, shipped as Supabase migrations, and a `supabase-auth-kit` command that installs them into your project. **Start here**: its README explains the whole model |
| [`@sirhc77/supabase-auth-kit-express`](packages/express) | Express 4 and 5 middleware |
| [`@sirhc77/supabase-auth-kit-fastify`](packages/fastify) | Fastify 5 plugin |
| [`@sirhc77/supabase-auth-kit-core`](packages/core) | The framework-agnostic layer the adapters share. Use it directly for jobs and scripts, or to write a binding for another framework |

## Getting started

In a project that already uses the Supabase CLI:

```bash
npm install --save-dev @sirhc77/supabase-auth-kit
npx supabase-auth-kit            # copy the kit's migrations into supabase/migrations
npx supabase migration up        # or: npx supabase db push
```

Then grant yourself the platform administrator role from the SQL editor:

```sql
select authz.provision_admin('you@example.com');
```

Then add an adapter to your server:

```bash
npm install @sirhc77/supabase-auth-kit-express   # or @sirhc77/supabase-auth-kit-fastify
```

```ts
const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
});

const auth = createExpressAuthKit({
    supabase,
    jwt: { jwksUrl: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`, issuer: `${SUPABASE_URL}/auth/v1` },
    resolveTenant: tenantFromParam("tenantId"),
});

app.use(auth.authenticate());
app.get("/t/:tenantId/invoices", auth.requireScope("invoices.read"), listInvoices);
```

The supabase-js client needs your project's secret key, and `authz` added to the API's exposed schemas: locally, `schemas` under `[api]` in `supabase/config.toml`; on a hosted project, the dashboard's API settings. **Grant nothing in `authz` yourself.** If you'd rather not expose the schema, pass a Postgres `query` function on a `postgres` connection instead of `supabase`.

The installer package's README covers [bootstrapping](apps/installer/README.md#bootstrap-the-first-administrator), [the model](apps/installer/README.md#the-model) and [the access posture](apps/installer/README.md#access-posture) in full. Each adapter's README covers its options, guards and error responses.

## Repository layout

```
apps/installer/            @sirhc77/supabase-auth-kit
  bin/                     the installer command
  supabase/schemas/        declarative SQL: the source of truth
  supabase/migrations/     generated migrations: what ships
  supabase/config.toml     the local development stack
packages/core/             @sirhc77/supabase-auth-kit-core
packages/express/          @sirhc77/supabase-auth-kit-express
packages/fastify/          @sirhc77/supabase-auth-kit-fastify
```

An npm workspaces monorepo, built with [Turborepo](https://turborepo.com). Every package is ESM and TypeScript. `typescript`, `vitest`, `pg` and `@supabase/supabase-js` are declared once, at the root, for building and testing.

## Development

You'll need Node.js and npm 11 (the repo pins `npm@11.19.1`), plus Docker to run the local Supabase stack.

```bash
npm install
npm run build    # tsc in every workspace, in dependency order
npm run test     # Vitest in every workspace; builds first
```

To build or test one package, pass its workspace name, for example `npm run build -w @sirhc77/supabase-auth-kit-express`. The root `lint` and `typecheck` scripts aren't wired up yet: `turbo.json` defines only `build` and `test`.

### The local Supabase stack

The integration tests run against a real database. They skip themselves when none is reachable, so `npm run test` passes without Docker, but the SQL is untested in that case. Start the stack from `apps/installer`; the Supabase CLI won't find the project from the repo root:

```bash
cd apps/installer
npx supabase start       # API :54321, database :54322, Studio :54323
npx supabase db reset    # rebuild the database from the migrations
```

The stack uses fixed ports. If another local Supabase project is already running, `supabase start` fails and the tests quietly run against that project's database instead, so stop the other one first (`npx supabase stop --project-id <id>`).

The integration suites run twice, once over a direct Postgres connection and once over supabase-js through the API. By default they use the local stack's database, API and fixed development keys. To point them elsewhere, set:

| Variable | Default |
| --- | --- |
| `AUTHZ_TEST_DATABASE_URL` | `postgresql://postgres:postgres@127.0.0.1:54322/postgres` |
| `AUTHZ_TEST_SUPABASE_URL` | `http://127.0.0.1:54321` |
| `AUTHZ_TEST_SUPABASE_SECRET_KEY` | The local stack's secret key |
| `AUTHZ_TEST_SUPABASE_PUBLISHABLE_KEY` | The local stack's publishable key |

### Changing the SQL

Migrations are **generated, never written by hand**:

1. Edit the declarative files in `apps/installer/supabase/schemas/`.
2. Generate a migration from the difference, then check it rebuilds cleanly:

   ```bash
   cd apps/installer
   npx supabase db diff -f <name>
   npx supabase db reset
   ```

3. Never edit a migration once it exists. Consumers have already installed it, so change the schema with a new one.

There are two deliberate kinds of exception, both written by hand because `db diff` can't see them: the bootstrap migration, which inserts data, and the privileges migrations, which set grants. That has a consequence: **any migration that adds a function to `authz` must revoke `PUBLIC EXECUTE` on it by hand**, and, if the core package calls it, grant it to `service_role` and add it to `AUTHZ_FUNCTIONS` in `packages/core/src/transport.ts`. Postgres grants `PUBLIC EXECUTE` to every new function, and `db diff` doesn't track privileges. `privileges.integration.test.ts` fails if any of that is missed.

Read [`apps/installer/supabase/CLAUDE.md`](apps/installer/supabase/CLAUDE.md) before changing anything about authorization, in SQL or in an adapter. It records why each rule exists and which design questions are still open. Keep the rules in SQL: the adapters call `authz.has_scope` and must never re-implement the tenant traversal in TypeScript.

### Releasing

Versions and publishing go through [Changesets](https://github.com/changesets/changesets). No release has been made yet, so run `npx changeset init` once first. After that:

```bash
npx changeset                  # describe a change
npx changeset version          # apply version bumps
npm run build
npm run changeset:publish      # changeset publish --no-git-tag --provenance
```

`--provenance` only works when publishing from a supported CI provider, such as GitHub Actions with `id-token: write` permission, so run the publish step from CI rather than locally.

## License

MIT
