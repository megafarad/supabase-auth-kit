# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`supabase-auth-kit` is an embedded AuthN/AuthZ library for Supabase, published as a set of scoped npm packages under `@sirhc77/`.

Authorization is hierarchical multi-tenancy in SQL: tenants form a tree with exactly one master (the single `parent_id IS NULL` row), principals (users **and** API keys) hold roles at tenants through `role_bindings`, and both role/scope *definitions* and *bindings* propagate down the tree — filtered, not truncated, at any tenant with `inherit = false`, which roles marked `crosses_boundary` pass through anyway. There is no membership table: membership **is** a live binding.

**The model lives in SQL; TypeScript only calls it.** `packages/core` wraps the schema — calling its functions by name over a direct Postgres connection or a secret-key supabase-js client — and holds the HTTP layer both adapters share (the guard order, the per-request scope memo, the errors); `packages/express` and `packages/fastify` bind it to their frameworks. Do not re-derive the traversal in TypeScript — `authz.has_scope(principal, tenant, scope)` is the predicate and `authz.tenant_chain(tenant)` is the one place the inherit/`crosses_boundary` rule is implemented.

## Where the detail lives

This file is deliberately thin. Each area documents itself in a nested `CLAUDE.md`, loaded when you touch files under it:

| File | Covers |
| --- | --- |
| `apps/installer/CLAUDE.md` | The published core package: local Supabase stack, the generate-never-hand-write migration pipeline, the consumer-facing installer bin, packaging |
| `apps/installer/supabase/CLAUDE.md` | **The `authz` model** — multi-tenancy, principals and identity claiming, roles/scopes and shadowing, built-ins, inheritance, the physical data model, the access posture and the function inventory, and the open design questions |
| `packages/core/CLAUDE.md` | **Framework-agnostic core** — the database seam, JWT verification, fail-closed rules, the write API |
| `packages/express/CLAUDE.md` | Express middleware adapter |
| `packages/fastify/CLAUDE.md` | Fastify plugin adapter |

Read `apps/installer/supabase/CLAUDE.md` before changing anything about authorization, in SQL or in an adapter. Its "Open questions" section lists design points that **must be asked about rather than guessed**.

## Workspaces

- `packages/core` → **`@sirhc77/supabase-auth-kit-core`**. Framework-agnostic. `jose` is its only runtime dependency, and the only one in the repo.
- `apps/installer` → **`@sirhc77/supabase-auth-kit`**. The published core package. Ships the SQL and a `supabase-auth-kit` bin.
- `packages/express` → **`@sirhc77/supabase-auth-kit-express`**. Express middleware over core. `express` is a peer dep, plus an aliased `express4` devDependency so the suite runs against both versions in the peer range.
- `packages/fastify` → **`@sirhc77/supabase-auth-kit-fastify`**. Fastify plugin over core. `fastify` (5.x only) + `fastify-plugin` are required peer deps.

## Commands

Root scripts fan out through Turborepo (`npm run <script>` at the root):

| Command | Notes |
| --- | --- |
| `npm run build` | `turbo run build` → `tsc` in each workspace |
| `npm run test` | `turbo run test` — Vitest in each workspace. Integration suites need a running local stack and skip themselves when the database is unreachable |
| `npm run lint` / `npm run typecheck` | Declared at the root but no `turbo.json` task or workspace script backs them; they no-op |
| `npm run changeset:publish` | `changeset publish --no-git-tag --provenance` |

Only `build` and `test` are defined in `turbo.json`. Adding a new task (lint, typecheck) requires both a `turbo.json` entry and a script in each workspace.

Single-package work: `npm run build -w @sirhc77/supabase-auth-kit-express` (or `turbo run build --filter=...`).

## Conventions

- ESM throughout (`"type": "module"`), TypeScript `module: NodeNext`, `strict: true`. Adapter packages compile with `declaration: true` from `src/` to `dist/`; the installer compiles from `bin/` to `dist/`. Every tsconfig pins `include` and `exclude` — without them `tsc` picks up previously emitted output and nests a stale `dist/src/`.
- `typescript`, `vitest`, `pg` and `@supabase/supabase-js` are declared once, in the root `devDependencies`, and shared by every workspace. The last is for the integration tests only: no package may depend on it at runtime. The root package is `private` so Changesets never tries to publish the workspace root. Tests live in each package's `test/`, outside the tsconfig `include`, so they never reach `dist`.
- Published packages declare `main`/`types`/`exports` pointing at `dist/`, and restrict `files` to what ships. The installer is bin-only and has no library entry point.
- SQL identifiers are `snake_case` throughout. Refer to columns by their real names (`crosses_boundary`, not `crossesBoundary`) — no camelCase mapping layer exists yet.
- Versioning and publishing go through Changesets (no `.changeset/` directory exists yet — `npx changeset init` before the first release).
