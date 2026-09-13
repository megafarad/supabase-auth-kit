# The `authz` model

Guidance for `apps/installer/supabase/` — the declarative schemas, the generated migrations, and the semantics they encode. See `../CLAUDE.md` for the migration pipeline that turns `schemas/` into `migrations/`, and the repo root `CLAUDE.md` for workspace-wide conventions.

**The model below is implemented in SQL and consumed by `packages/core`.** `000_auth_kit_tables.sql` has the tables, `001_auth_kit_functions.sql` has identity provisioning, claiming, the resolver, the write functions and the read functions, and `002_auth_kit_policies.sql` has the SELECT-only RLS policies — under posture A those policies are dormant, and the enforcement path is the functions, reached from `packages/core` (over a direct connection or supabase-js) through the Express and Fastify adapters. Changes to the model belong in those functions, not in a new traversal.

## Hierarchical multi-tenancy

Tenants form a tree. Each tenant may have a `parent_id` pointing to another tenant. **Exactly one master tenant exists, identified as the single row with `parent_id IS NULL`** — there is no `is_master` column, no other tenant may be parentless, and the master owns the base role/scope set. It is the base case of the resolution recurrence below. Roles and scopes assigned at a parent tenant propagate downward, and an authorization check considers a tenant's ancestor chain rather than the tenant alone — but an `inherit = false` tenant filters that chain, so ordinary propagation reaches only an unbroken run of inheriting descendants while roles marked `crosses_boundary` pass through regardless (see [Inheritance](#inheritance)).

**Bindings propagate, not just definitions.** A `role_bindings` row granting a principal a role at tenant T grants that role at T *and at every descendant of T*. An authorization check for a principal at tenant X therefore matches bindings whose `tenant_id` is X **or any ancestor of X reachable without crossing a cut**, plus bindings of `crosses_boundary` roles from any ancestor at all — the resolver walks up from X and does not require a binding at X itself. Two consequences: `role_bindings_tenant_id_idx` sits on the hot path of every check, and since `(principal_id, role_id, tenant_id)` is unique per tenant rather than per subtree, a principal can hold redundant bindings at both a parent and one of its descendants — the effective grant set is a union over the chain, deduped on `role_id`.

## Principals

Both **users** (authenticated via Supabase JWT) and **API keys** (authenticated via hashed key lookup in PostgreSQL) are principals. A principal can hold one or more roles at one or more tenants.

**There is no membership table — membership *is* `role_bindings`.** "X belongs to tenant T" has no representation beyond "X holds at least one live binding at T", and there is no way to be a member of a tenant while holding no role there. This trips people up, because the obvious guesses are all wrong:

| Operation | Scope |
| --- | --- |
| Add an existing person to a tenant | `authz.bindings.grant` |
| Invite someone with no account yet | `authz.bindings.grant`, via `authz.invite_user()` |
| Remove someone from a tenant | `authz.bindings.revoke` |

None of them involve `authz.users.write`. That scope controls the *global* person lifecycle — `disabled_at` and `deleted_at`, which apply across every tenant at once — so it is a platform-operator power and is the one scope `tenant_admin` does not hold. Provisioning an unclaimed identity during an invite is a side effect of granting to an address that has none, not a separate capability: the row is inert until claimed, so it confers nothing on its own.

`authz.users` has no `tenant_id`, so any read policy on it must derive scope through bindings — "people holding a binding at a tenant you can read users at", plus yourself. An unscoped `users.read` would let one tenant's admin enumerate every address on the platform. Lookup by email during an invite avoids that by happening inside `invite_user()` rather than through a table read.

**`authz.users` is the identity record; `auth.users` is the authentication attachment.** `auth_user_id` is nullable, so a person can be provisioned by email before they have an account — `authz.provision_admin('me@example.com')` creates the identity, its principal, and a self-granted binding without any `auth.users` row existing. Such a row is inert by construction: authorization matches a JWT's `sub` against `auth_user_id`, and NULL never matches, so an unclaimed identity grants nothing.

`authz.claim_auth_user()` links the two when the person actually signs up, matching on `email_id` — the SHA-256 of the lowercased, trimmed address, computed by `authz.email_id()`. **Provisioning and claiming must agree on that hash exactly**, which is why both go through the one function rather than inlining `encode(sha256(...))`. The claim fires only once `email_confirmed_at` is set; claiming at signup would let anyone who knows a provisioned address register under it and take the grants waiting there. A signup with no provision waiting gets a fresh identity and principal holding no roles at all.

**`claimed_at` separates "never claimed" from "retired".** It is set the first time an identity is linked and never cleared — including when `ON DELETE SET NULL` nulls `auth_user_id` because the Supabase account was deleted. So `auth_user_id IS NULL AND claimed_at IS NULL` is a provision waiting to be taken, while `auth_user_id IS NULL AND claimed_at IS NOT NULL` is a retired identity, and the trigger claims only the former. Re-registering a departed administrator's address therefore inherits nothing.

The fail-closed edge: that newcomer gets **no** `authz.users` row at all, because `users_email_id_uq` blocks a second row on the address. They authenticate normally and hold zero authorization, which is the safe direction, but it is a state downstream code must tolerate — an authenticated user with no authz identity. `authz.reclaim_identity(email)` is the deliberate way back, for when an account was deleted and recreated for the *same* person; it refuses to act on an identity that is still linked, and the grants survive the relink, so confirm who owns the address first.

## Roles and scopes

Roles are named bundles of scopes (permissions). They are defined per-tenant but inherited downward through the hierarchy. A root "master" tenant defines the base set of roles and scopes that tenants inherit by default (`inherit = false` opts out — see [Inheritance](#inheritance)). Child tenants may define additional roles and scopes for themselves. When resolving roles/scopes for a tenant, the ancestor chain is walked — the tenant's own definitions plus its ancestors', up to the master root or the first cut, whichever comes first — with crossing roles exempt from the cut.

**Nearest definition wins.** A child defining a role or scope under a name it would otherwise inherit *shadows* the inherited one: resolution walks upward from the tenant and keeps the first definition it finds for each name. Shadowing is per-name and independent between roles and scopes — a child may shadow one role and inherit every other.

**Shadowing governs name resolution only.** `roles` and `scopes` rows carry distinct UUIDs per tenant, and `role_bindings.role_id` / `role_scopes.scope_id` name specific rows — shadowing never retargets them. A binding issued against master's `admin` keeps master's scopes at every tenant it reaches, even where a child has defined an `admin` of its own. The two resolutions therefore key on different things: definition lookup keys on `(kind, name)` and takes the nearest, while grant resolution keys on `role_id` and unions. A child cannot alter what an already-issued grant confers.

## Built-ins

The bootstrap migration seeds the master tenant, two roles, and 14 scopes, all under the reserved UUID prefix `a0000000-0000-4000-8000-…` so built-in rows are recognisable at a glance.

- **`admin`** — all 14 scopes, `crosses_boundary = true`. The platform operator.
- **`tenant_admin`** — 13 scopes, everything but `authz.users.write`, `crosses_boundary = false`. What a workspace owner holds at their own tenant. Keeping it a distinct row from `admin` also keeps audit queries able to tell an operator from a customer who happens to own a workspace.

`tenant_admin` not crossing boundaries is the deliberate, weaker default: if a sub-tenant sets `inherit = false` its parent's tenant_admins lose reach into it, which is a visible failure the operator can always repair because `admin` does cross. The opposite default would silently deny sub-tenants any isolation from the tenants above them.

Scopes are named `authz.<resource>.<action>` — the `authz.` prefix keeps them from colliding with the application scopes a consumer defines. They cover the schema's own administration (`tenants`, `users`, `roles`, `scopes`, `bindings`, `api_keys`, `audit`), and the `admin` role holds all of them. Two of the splits are deliberate:

- **`bindings.grant` is separate from `bindings.revoke`.** Granting is escalation and revoking is de-escalation, so revoke can be delegated to support or incident response on its own.
- **`authz.roles.write` is the most dangerous scope in the set.** Shadowing does not retarget bindings, but editing the bound role row does: `role_bindings.role_id` → `role_scopes` means adding a scope to a role widens every existing binding to it, including ones issued at master and propagated down. Keep it out of any delegated tenant-admin role.

The `admin` role is `crosses_boundary = true`, and that is load-bearing rather than incidental — without it a tenant setting `inherit = false` cuts off the role's definition *and* every propagated binding to it, locking the platform operator out of a tenant that tenant administers.

## Inheritance

A tenant marked `inherit = true` receives its ancestors' role and scope *definitions* and their role *bindings*. A tenant marked `inherit = false` receives **neither** — the flag gates both, so such a tenant sees only what is defined and bound on itself.

`inherit` is read on the tenant carrying it and governs that tenant's own edge to its parent. **Resolution is compositional** — a tenant's effective set is defined against its parent's effective set, not by a flat scan of the chain. Definitions and bindings share that shape but combine differently:

```
defs(T)  = own_defs(T)                                -- T is the master
defs(T)  = own_defs(T)  ⊲ defs(parent(T))             -- T.inherit = true
defs(T)  = own_defs(T)  ⊲ crossing(defs(parent(T)))   -- T.inherit = false

binds(T) = own_binds(T)                               -- T is the master
binds(T) = own_binds(T) ∪ binds(parent(T))            -- T.inherit = true
binds(T) = own_binds(T) ∪ crossing(binds(parent(T)))  -- T.inherit = false
```

`crossing(S)` keeps only those members of S whose role has `crosses_boundary = true`, carrying that role's scopes through `role_scopes`. The two combining operators differ, and that difference *is* shadowing:

- `⊲` is a **left-biased merge keyed on `name`** — `own_defs(T)` beats anything of the same name arriving from the parent. This is where a child shadows an inherited role or scope.
- `∪` is a **plain union keyed on `role_id`** — bindings never shadow. A propagated binding keeps naming the exact role row it was issued against, so a principal can hold master's `admin` and a child's `admin` at the same tenant at once, with their scopes unioned.

The scopes a principal holds at T are therefore the union, over every binding in `binds(T)` for that principal, of the scopes attached to *that binding's* `role_id` through `role_scopes` — never the scopes of whatever `defs(T)` resolves that name to.

So a cut **filters rather than truncates**. Two things follow:

- Ordinary (non-crossing) content stops dead at the first cut. Given Master → A → B → C with `B.inherit = false` and `C.inherit = true`, C sees C's and B's own sets but none of A's or Master's ordinary roles, scopes, or bindings — C's `inherit = true` keeps its edge to B intact but buys it nothing above B.
- Crossing roles flow to the entire subtree. A role marked `crosses_boundary` at Master reaches every tenant below it, through any number of cuts. Because the filter composes, what crosses into B is part of B's effective set, and C inherits B's effective set wholesale — so C gets Master's crossing roles even though it can't see Master's ordinary ones.

Note the asymmetry this creates — `crosses_boundary` exists on `roles` and has no counterpart on `scopes`. A scope cannot cross a boundary on its own; it reaches a non-inheriting tenant only by hanging off a crossing role through `role_scopes`. Granting a scope past a boundary means putting it on a role marked `crosses_boundary`, not marking the scope.

## Data model (`authz` schema)

All tables live in a dedicated `authz` schema, separate from Supabase's `auth` and `public`. The semantics are the sections above; this section is the physical shape only.

- **`principals` is the unifying actor type.** A principal is exactly one of a `user` or an `api_key`, enforced by the `principals_exactly_one_of` check plus partial unique indexes on each FK. Everything that grants or audits references `principal_id`, not `user_id` — new actor kinds extend the enum rather than the grant tables.
- **`authz.users` attaches to `auth.users`** through a **nullable** `auth_user_id`. The two are deliberately separate: Supabase owns authentication, this schema owns authorization, and `authz.users` carries both the soft-delete/disable lifecycle and the pre-signup provisioning that `auth.users` cannot. `users_auth_user_id_uq` is unique rather than plain — Postgres treats NULLs as distinct, so unlimited unclaimed rows coexist while claimed rows stay one-to-one with `auth.users`. `email_id` (unique, `char(64)`) is the join key for claiming. The FK is `ON DELETE SET NULL`: deleting the Supabase account unlinks the identity rather than blocking the delete or cascading it away, leaving the authz row, its bindings and its audit trail intact.
- **`tenants.parent_id` is a nullable self-reference** forming the tree, alongside a `boolean inherit` defaulting to `true`. `parent_id IS NULL` identifies the master tenant and must match exactly one row. `tenants_single_master_uq`, a unique index on the expression `(parent_id IS NULL)` partial to `WHERE parent_id IS NULL`, enforces *at most* one; the seed supplies the one. The database can only enforce the upper bound, so a missing master is a runtime condition, not a constraint violation.
- **Roles and scopes are tenant-owned**, each unique on `(tenant_id, name)` and joined many-to-many through `role_scopes`. `roles.crosses_boundary` is the `inherit = false` override described under [Inheritance](#inheritance); the per-tenant uniqueness is what permits a child to shadow an inherited name, resolved nearest-first under [Roles and scopes](#roles-and-scopes).
- **`role_bindings` is the grant record**: `(principal_id, role_id, tenant_id)` unique, with `granted_by_principal_id`, `granted_at`, `expires_at`, and `revoked_at`. Grants are revoked by timestamp, never deleted. The `tenant_id` is the *root* of the grant, not its full extent — the binding reaches every descendant of that tenant, so this table is read through the ancestor chain rather than by exact match.
- **Soft deletion everywhere**: `disabled_at` / `deleted_at` / `revoked_at` columns, with indexes on them. Queries must filter these explicitly.
- **`api_keys` stores `key_hash` (char(64), i.e. SHA-256 hex) plus a unique `key_prefix`** for lookup — the plaintext key is never stored. `users.email_id` is the same char(64) shape, a hash used as the unique lookup key alongside the plaintext `email`.
- **`audit_logs` captures `before`/`after` jsonb** alongside request context (`request_id`, `method`, `route`, `ip`, `user_agent`).
- **RLS is enabled on every table, with SELECT-only policies in `002_auth_kit_policies.sql`.** Any new table needs a matching `enable row level security` line and a policy, or it is deny-all.

## Access posture (decided: A, server-only)

**Only the server reaches `authz`, and never as `anon` or `authenticated`.** Nothing is `GRANT`ed to either of them, and they have no `USAGE` on the schema. The server reaches it one of two ways, and core treats both the same:

- **A direct Postgres connection as `postgres`**, the owner of the tables and functions (`fromQuery`). `service_role` cannot be used here: in Supabase it is `NOLOGIN`, a role PostgREST switches into and nothing else.
- **supabase-js holding the secret key, through PostgREST** (`fromSupabase`). That is `service_role`, and it works because `20260913040000_auth_kit_rpc_privileges.sql` grants it `USAGE` on the schema and `EXECUTE` on **exactly** the functions core calls (`AUTHZ_FUNCTIONS` in `packages/core/src/transport.ts`, held equal by an integration test). The project must also add `authz` to its exposed schemas. That is project configuration, not something a migration can do; `config.toml` does it for the local stack.

Neither role is subject to RLS — the owner bypasses it, `service_role` has `BYPASSRLS` and no table grants anyway — so **the functions in `001` are the enforcement path, and the RLS policies in `002` are dormant defence in depth**. The functions taking an explicit actor are safe to expose to `service_role` only because whoever holds a secret key is already trusted to name any actor.

Exposing the schema changes what the grants are worth. While `authz` was unexposed, a stray grant was unreachable; now `service_role`'s `EXECUTE` set is reachable over HTTP by anyone holding the secret key, and an `anon` grant would be reachable by anyone at all. Hence three rules:

- **Grant `service_role` function by function, never by default.** The rpc privileges migration revoked the default privilege `20260909060000` had set, so a new function is callable by nobody until a migration grants it. `provision_admin`, `reclaim_identity`, `claim_auth_user`, `bindings_in_force` and every internal helper stay ungranted.
- **Never grant anything in `authz` to `anon` or `authenticated`.** Supabase's own guide to exposing a custom schema does exactly that, for all routines; a consumer following it would hand the public key `provision_admin`. The installer and the READMEs warn about it, and `privileges.integration.test.ts` fails if either role can reach anything.
- **Never overload a function name.** PostgREST passes arguments by name and cannot tell overloads apart; a test asserts there are none.

Verified over HTTP: the publishable key and no key both get `42501 permission denied for schema authz`; the secret key gets `42501` on `provision_admin`; PostgREST's OpenAPI listing for `service_role` shows exactly the granted functions.

The policies are **SELECT-only**, deliberately. Every guarded write already has a `SECURITY DEFINER` function carrying its rules, so `WITH CHECK` clauses would duplicate each escalation rule somewhere it can drift — and RLS cannot express some of them anyway, since `WITH CHECK` never sees the old row. With no INSERT/UPDATE/DELETE policy, RLS denies all three by default: verified that `GRANT ALL` plus a platform-operator JWT still gets `new row violates row-level security policy` on insert, and `UPDATE 0` / `DELETE 0` on the others.

They are `to public` rather than `to authenticated` so a role later granted access is governed by the rule rather than blocked outright, and every policy calls a `SECURITY DEFINER` predicate rather than subquerying an authz table — a policy that reads another RLS-protected table has that table's policies applied inside it, which silently narrows results and can recurse. `current_principal_id()` is wrapped in a scalar subselect so the planner hoists it to an InitPlan instead of calling it per row.

Verified by temporarily granting inside a rolled-back transaction: a tenant admin at `acme` sees only `acme` — 1 of 3 tenants, 1 of 3 users, 1 of 2 API keys, 1 of 3 bindings — while the platform operator sees everything (`admin` crosses boundaries), and a session with no JWT sees zero rows everywhere rather than erroring.

**`PUBLIC EXECUTE` has been revoked** from every `authz` function by `20260909060000_auth_kit_privileges.sql`, so a future `GRANT USAGE` on the schema no longer exposes anything by itself. That mattered most for the two functions carrying no authorization check at all by design — `provision_admin(email)` hands out master admin, `reclaim_identity(email)` relinks a retired identity to whoever now holds the address. Both are SQL-editor bootstrap tools.

`postgres` owns the functions and holds `EXECUTE` implicitly, so no revoke touches the owner connection. `20260909060000` first granted `service_role` `EXECUTE` on everything, with a default privilege carrying that onto new functions; `20260913040000` replaced both with the explicit list above. `supabase_auth_admin` is granted `EXECUTE` on `claim_auth_user()` specifically so revoking `PUBLIC` cannot break signup; verified end to end against the live Auth API, not just by direct insert.

**Remaining prerequisites for posture B** — exposing `authz` to `authenticated`, which is a different posture from the server-only exposure above. JWT-bound wrapper overloads for the 13 explicit-actor write functions, so no caller can pass an arbitrary actor — the explicit-actor forms must never be granted. `verify_api_key` must never be granted at all: it takes a key, writes `last_used_at`, and would make the API a key-testing oracle. The policies in `002` name six functions directly (`has_scope`, `can_read_user`, `can_read_principal`, `role_tenant_id`, `current_principal_id`, `master_tenant_id`) and `authenticated` would need `EXECUTE` on those; three take a principal parameter, so granting them lets any user probe another principal's authority. Fixing that means JWT-bound predicate variants, which costs the InitPlan hoist that currently evaluates the principal once per query instead of once per row. Prefer a separate exposed `authz_api` schema of `security_invoker` views and distinctly-named wrappers over exposing `authz` itself — that keeps `key_hash` out structurally and avoids PostgREST overload ambiguity.

Also note `current_principal_id()` propagates a cast error rather than returning null if `request.jwt.claims` carries a non-UUID `sub`; that denies the query rather than opening it, but it is noisy.

Policies call the resolver in `001_auth_kit_functions.sql` rather than re-deriving the traversal. `authz.has_scope(principal, tenant, scope)` is the predicate, with `authz.current_principal_id()` bridging the JWT.

The whole inherit/`crosses_boundary` rule lives in one place, `authz.tenant_chain(tenant)`. It returns the ancestor chain with a `crossed` flag per row, latched on by stepping *out of* an `inherit = false` tenant — `crossed := crossed OR NOT t.inherit` — so that tenant's own rows stay unfiltered while everything above it is filtered to crossing roles. That single upward pass is equivalent to the compositional definition because `crossing()` is a filter and so distributes over the union; the recursion in the spec does not need a recursive implementation. Everything else builds on it:

| Function | |
| --- | --- |
| `tenant_chain(tenant)` | ancestor walk + the `crossed` flag; depth-capped at 64 against cycles |
| `effective_roles(tenant)` | role defs, `distinct on (name) order by depth` — the left-biased merge |
| `effective_scope_defs(tenant)` | scope defs; past a cut only those hanging off a crossing role |
| `bindings_in_force(tenant)` | every live grant in force at a tenant, for any principal — the one place grants are read. **Invoker, not definer, with no `SET`**, so it inlines; see below |
| `effective_bindings(principal, tenant)` | `bindings_in_force` narrowed to one principal |
| `effective_scopes(principal, tenant)` | scope names held, via each binding's own `role_id` |
| `has_scope(principal, tenant, scope)` | the RLS predicate |
| `current_principal_id()` | JWT → principal; delegates to the next row |
| `principal_for_auth_user(auth_user_id)` | auth.users id → principal. The parameterized form adapters use, since a direct connection has no `request.jwt.claims` GUC for `auth.uid()` to read |
| `can_read_user` / `can_read_principal` / `role_tenant_id` | policy predicates for `002` |
| `master_tenant_id()` | the single parentless tenant, or null |
| `grant_role(actor, principal, role, tenant, expires)` | the grant primitive; enforces the rules below |
| `invite_user(actor, tenant, email, role)` | identity handling, then `grant_role` |
| `create_role(actor, tenant, name, desc, crossing)` | role creation; `crossing` is master-gated |
| `update_role(actor, role, name, desc, crossing)` | amend in place; null leaves a column alone |
| `add_role_scope(actor, role, scope)` | attach; refuses a scope the actor lacks |
| `remove_role_scope(actor, role, scope)` | detach; narrowing needs no holds-it check |
| `principal_is_active(principal)` | is somebody actually behind this principal |
| `create_tenant(actor, parent, name)` | child tenant; grants nothing, by design |
| `create_workspace(actor, name)` | top-level workspace + self-granted `tenant_admin` |
| `update_tenant(actor, tenant, name, inherit)` | rename needs write here, `inherit` needs it at the **parent** |
| `revoke_binding(actor, binding)` | revoke by timestamp; idempotent |
| `create_scope(actor, tenant, name, desc)` | `authz.`-prefixed names are master-only |
| `create_api_key(actor, tenant, label, expires)` | returns the plaintext **once** |
| `verify_api_key(key)` | key → principal, or null; the API-key half of `current_principal_id()` |
| `revoke_api_key(actor, key)` | revoke by timestamp; idempotent |
| `get_tenant(actor, tenant)` | one tenant, with `tenants.read` there |
| `list_child_tenants(actor, parent, limit, after)` | children with `tenants.read`; inheriting children answered by one check at the parent |
| `list_principal_bindings(actor, principal, limit, after)` | a principal's live bindings: all of them to themselves, else where the actor has `bindings.read` |
| `list_tenant_bindings(actor, tenant, include_inherited, limit, after)` | a tenant's members, pending invites included |
| `list_roles` / `list_scopes(actor, tenant, limit, after)` | definitions in effect at a tenant, after shadowing |
| `list_role_scopes(actor, tenant, role, limit, after)` | what a role in effect at a tenant confers |
| `list_api_keys(actor, tenant, limit, after)` | keys issued at a tenant; **never `key_hash`** |

**Mutating functions take the actor explicitly rather than reading the JWT.** An adapter holds a direct `postgres` connection with no `request.jwt.claims` set, so `auth.uid()` is null there, and API-key principals never carry a JWT at all — both resolve the caller themselves and pass it in. `current_principal_id()` is for a JWT-bound wrapper overload, which is the only form that should ever be granted to `authenticated`; the explicit-actor form must not be, or any caller could impersonate any principal.

**`grant_role` is the grant primitive; `invite_user` is identity handling layered on it.** `invite_user` resolves an address to a principal — finding or provisioning the identity — then delegates. It is the only way to grant anything to an **api_key** principal, which has no address to invite.

Two details in it are load-bearing. It **upserts** rather than `on conflict do nothing`: `(principal_id, role_id, tenant_id)` is unique whether or not the binding is revoked, so a do-nothing conflict would make re-granting a previously revoked role a silent no-op, leaving the caller believing access was restored when it was not. And `invite_user` re-checks authority **before** its identity lookup even though `grant_role` checks it again — the retired-identity error names an address, so checking afterwards would let an unauthorised caller probe which addresses have retired identities.

`grant_role` enforces the rule the whole scope split depends on: **you cannot grant what you do not hold.** Every scope the granted role confers must already be held by the actor at that tenant, and the role must resolve at that tenant. Without it, `authz.bindings.grant` alone would be equivalent to full administration — bind yourself to `admin` and take all 14 scopes. It also refuses to bind a *retired* identity, since `claim_auth_user()` would never hand that row to the new signup and the binding could never be exercised.

**`crosses_boundary` is master-gated, and that is what makes the rule above airtight.** "What you hold" is bounded per tenant, but a crossing role reaches past `inherit = false` throughout its owner's subtree — into tenants where the granter cannot act. Minting one is therefore a way to manufacture reach you do not have, and it is the single escalation the grant rule does not close by itself. `create_role` requires `authz.roles.write` at the tenant for an ordinary role and *additionally* at the master to set the flag. With that in place the only crossing role a tenant admin ever sees is the seeded `admin`, and granting that already demands all 14 scopes including `authz.users.write`, which `tenant_admin` does not hold.

`update_role` gates a change to `crosses_boundary` in **both directions**, which is not symmetry for its own sake. Turning it on manufactures reach; turning it off *strips* reach the operator was relying on, so a tenant admin must not be able to un-cross a role the operator placed inside their tenant. Passing the value a role already has is a no-op and stays unguarded, so ordinary edits don't need master authority. `tenant_id` is deliberately not updatable — moving a role between tenants needs authority at both ends and is a different operation.

`add_role_scope` carries the companion rule to `invite_user`'s: an actor may only attach a scope they already hold at the role's tenant. Without it, `authz.roles.write` would be its own escalation, since `role_scopes` is keyed by id and bindings point at role rows — attaching a scope widens every existing binding to that role, including ones issued higher up and propagated down. `remove_role_scope` has no such check, because narrowing cannot manufacture authority. It is also the one hard delete in the schema: `role_scopes` carries no `revoked_at`.

**`create_tenant` deliberately grants nothing.** Bindings propagate downward, so an actor holding `authz.tenants.write` at the parent holds it at the child the moment that child exists; a binding there would be a second row conferring nothing new and one more thing to unwind on revocation. It also takes no `inherit` argument — a child created with `inherit = false` would immediately cut its creator off unless their role crosses, which is a self-inflicted lockout, so opting out belongs in a later deliberate edit.

**`create_workspace` is the one function with no scope check, and that is deliberate.** Every permission derives from a binding and a fresh signup holds none, so no scope could gate it; it requires only `principal_is_active`. The kit ships the mechanism and the consumer owns the policy — expose it for open signup, put it behind a plan or an invite, or never expose it and have an operator use `create_tenant` instead. Nothing bounds how many workspaces a principal creates, so rate limiting is the caller's problem. Workspaces are always children of the master, since `tenants_single_master_uq` forbids a second root: master is the platform, its children are the customers.

**The `authz.` scope namespace is reserved to the master.** `scopes` is unique per `(tenant_id, name)` and authorization resolves scopes **by name**, so a tenant defining its own `authz.users.write` would genuinely hold that permission throughout its subtree — forging the built-in vocabulary is a direct route from `authz.scopes.write` to full administration. `create_scope` therefore requires `authz.scopes.write` at the master for any `authz.`-prefixed name.

That reservation is load-bearing for `add_role_scope`, which accepts a scope the actor does **not** hold if they hold `authz.scopes.write` at the tenant that *owns* the scope. Without that clause a newly created scope would be permanently unattachable by anyone, the operator included — nobody holds a scope that no role confers yet, so a pure holds-it check deadlocks every `create_scope`. The clause is safe only because a tenant admin can never own an `authz.` definition.

**API keys.** `create_api_key` returns the plaintext once and stores only its SHA-256, in the same `char(64)` hex shape as `users.email_id`; the `key_prefix` is the unique lookup key. `verify_api_key` is the API-key half of `current_principal_id()` — adapters turn a header into an actor they can pass to the write functions, since an API key carries no JWT. It returns null for unknown, wrong, revoked and expired alike, and updates `last_used_at`, which is one row-level write per authenticated request.

An API key **cannot mint another API key**: `created_by_user_id` is `NOT NULL` and an api_key principal has no user behind it. That is a useful ceiling rather than an inconvenience — key material never begets more key material without a person in the loop. Revoking a key withdraws everything its principal held without unwinding any bindings, because `effective_bindings` filters on `api_keys.revoked_at`.

**`update_tenant` anchors `inherit` on the parent, not on the tenant being edited.** Renaming is an ordinary edit needing `authz.tenants.write` at the tenant itself, but cutting a tenant off severs the reach of everyone whose authority over it comes from above — so without the parent anchor, somebody bound only at a sub-tenant could set `inherit = false`, escape their parent's oversight, and keep their own access. That is the mirror image of minting a crossing role, and since bindings propagate downward and never upward, anchoring on the parent denies exactly that caller and no one else. Changing `inherit` on the master is refused outright: it has no parent to inherit from.

The parent anchor also makes a cut **self-healing**. An administrator who cuts off a child loses reach into it — verified, and expected — but still holds authority at the parent, so they can always set it back without escalating to the operator.

`revoke_binding` exists because RLS cannot express it: `WITH CHECK` sees only the new row, never the old, so "may set `revoked_at` and nothing else" is not writable as a policy. It is anchored on the binding's own tenant, so a grant issued at the master can only be revoked by someone with authority there. It needs no holds-it check — revocation only narrows — and it is idempotent, preserving the original `revoked_at` so a retry cannot quietly rewrite when access ended.

`principal_is_active` asks a **different** question from the filter inside `effective_bindings`, which is why they are not shared. That one asks what a principal *would* hold and admits unclaimed identities on purpose, so an admin view can see grants waiting for someone who has not signed up. This one asks whether somebody is actually behind the principal, so an unclaimed identity fails — nobody can have authenticated as one.

These guards live in the functions, not in constraints, so they bind callers going through the sanctioned API — which under posture A is every caller, since only the server can reach the schema at all. Note also that no table has an `updated_at` trigger; functions that amend rows set it explicitly, and a direct `UPDATE` that forgets to will leave it stale.

The read helpers are `stable` and `security definer` — the owner bypasses RLS, so these are the only sanctioned read path — with one deliberate exception, below.

**`bindings_in_force` is an invoker function on purpose.** `security definer` and a `SET` clause each stop Postgres inlining a SQL function, and inlining is what lets the planner push `effective_bindings`' principal filter into the query. Measured with 20k bindings at one tenant: as an opaque definer call, `has_scope` got 35× slower, because every check materialised the whole tenant's bindings first; inlined, it costs what it did when the query lived inside `effective_bindings`. It is safe only while nothing but the owner can execute it — it then runs inside the definer functions that call it, as the owner, under their empty `search_path`. Never grant it.

## Reads

**Reads are functions, shaped like the writes**: explicit actor, `security definer`, the rule inside. They answer the policies' visibility questions, and `reads.integration.test.ts` claims real identities in a rolled-back transaction and asserts the two agree on every row set they share: child tenants, a tenant's API keys, a tenant's own bindings, and a principal's bindings.

- **Refusal is filtering, never an exception** — zero rows, as RLS returns, so a read cannot probe what exists.
- **Resolved where a policy is per-row.** `list_roles`, `list_scopes` and `list_role_scopes` answer "what is in effect at this tenant" and gate on the read scope *at that tenant*. The `roles` policy gates each row on its owning tenant instead, which would hide every inherited role — `tenant_admin` included — from a tenant admin. This is a deliberate divergence from the policies, not an oversight, and it is why those three are excluded from the parity test.
- **Your own bindings are always visible**, as in the `role_bindings` policy, and **membership reveals names**: your own binding shows its tenant's and role's names without `tenants.read`/`roles.read`, because a tenant switcher that cannot name your tenants is useless.
- **Member details are gated where the binding was made.** `list_tenant_bindings` shows email with `users.read` at the binding's own tenant. That is narrower than `can_read_user`, which also admits someone readable through another tenant, and it is deliberate: `can_read_user` is a query per row, and ordering by email would force it onto every member of the tenant, not just one page.
- **Inherited bindings are opt-in** (`include_inherited`), because under the master they include the platform operators. Each is still shown only with `bindings.read` where it was made, so a tenant admin sees none from above.
- **Lists page by keyset.** PostgREST truncates RPC results at `max_rows` (1000) silently, so nothing returns an unbounded set. `page_cursor` is the row's id followed by its sort key — ids are fixed-width, so no delimiter is needed. `p_limit` is clamped to [1, 1000].

Two performance rules the reads depend on, both measured on 20k members:

- `list_tenant_bindings` computes authority once per tenant in the chain, in a CTE marked **`MATERIALIZED`**. Without it Postgres inlines the CTE and runs the `has_scope` calls per member row: 43 seconds per page, against ~125 ms.
- `list_child_tenants` answers every *inheriting* child with one check at the parent. That is sound because an inheriting child receives every binding in force at its parent, so authority there implies authority at the child; only `inherit = false` children need their own check. It keeps listing the master's workspaces cheap for an operator. For a caller *without* authority at the parent it still checks every child, so it is not a way to find your own tenants — `list_principal_bindings` is.

## Open questions

Unresolved design points. Each one changes what a correct resolver does, and none can be answered from the schema. **Ask rather than guessing.**

1. ~~**Is an authenticated user with no authz identity handled everywhere?**~~ **Settled for SQL, Express and Fastify.** SQL is fail-closed (`current_principal_id()` null, `has_scope(null, …)` false, policies return zero rows). `packages/core` short-circuits a null principal to zero scopes *without querying*, with unit tests asserting both the answer and that the query stub was never called, plus an integration test that SQL agrees. `packages/express` answers **403** — a credential that verified but maps to no identity — distinguished from **401** for no credential at all, tested on Express 4 and 5 with an assertion the handler never ran. `packages/fastify` gives the same answers through the same code — the guard order now lives once, in core's `enforceGuard` — and the same two tests are ported to Fastify 5, again asserting the handler never ran.

