# @sirhc77/supabase-auth-kit

Embedded authorization for Supabase: hierarchical multi-tenancy, roles and scopes, and API keys, implemented in SQL inside your own Supabase Postgres database.

This package ships the SQL and a small installer that copies it into your project's migrations. Your server talks to it through one of the framework adapters:

| Package | Use it for |
| --- | --- |
| `@sirhc77/supabase-auth-kit` | The `authz` schema: tables, functions, bootstrap data, and the installer (this package) |
| [`@sirhc77/supabase-auth-kit-express`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-express) | Express 4 and 5 middleware |
| [`@sirhc77/supabase-auth-kit-fastify`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-fastify) | Fastify 5 plugin |
| [`@sirhc77/supabase-auth-kit-core`](https://www.npmjs.com/package/@sirhc77/supabase-auth-kit-core) | The framework-agnostic layer the adapters share. You rarely install it directly |

## How it works

- **Tenants form a tree.** Exactly one tenant, the *master*, has no parent. Your customers' workspaces are its children, and they can have sub-tenants of their own.
- **Principals are users and API keys.** Supabase handles authentication. The kit keeps an authorization identity for each person and each key.
- **Roles bundle scopes.** A scope is a single permission, such as `authz.roles.read` or `invoices.write`. A role is a named set of scopes, defined at a tenant.
- **Bindings grant roles.** A binding gives a principal one role at one tenant. There is no separate membership table: a principal is a member of a tenant because it holds a live binding there.
- **Everything propagates down the tree.** A role granted at a tenant applies at every tenant below it, and the roles and scopes a tenant defines are visible to its descendants.
- **The check lives in SQL.** `authz.has_scope(principal, tenant, scope)` answers every authorization question, and the adapters ask the database rather than re-implementing the rules in TypeScript.

## Install

Run these commands from your project root, the directory that contains `supabase/`:

```bash
npm install --save-dev @sirhc77/supabase-auth-kit
npx supabase-auth-kit
```

The installer copies every migration in the package into `./supabase/migrations/`, creating the directory if it doesn't exist. Apply them the way you apply any other migration:

```bash
npx supabase migration up   # local stack
npx supabase db push        # linked hosted project
```

Each copy is named `<timestamp>_supabase_auth_<original name>.sql`. The timestamp uses Supabase's own `YYYYMMDDHHMMSS` format and is always later than your newest existing migration, so the kit's migrations apply after yours. The installer uses the `_supabase_auth_` marker to recognise migrations it has already installed, so running it twice does nothing the second time.

### Upgrading

Upgrade the package and run the installer again. It copies only the migrations your project doesn't have yet. Don't edit an installed migration: the next upgrade builds on it as shipped.

## Bootstrap the first administrator

A fresh install contains the master tenant, the built-in roles, and their scopes, but nobody holds any of them yet. From the Supabase SQL editor, or any `psql` session connected as `postgres`, run:

```sql
select authz.provision_admin('you@example.com');
```

This creates an identity for that address and grants it the `admin` role at the master tenant. You can run it before the person has an account: the identity waits, inert, until someone signs up with that address and confirms it. At that point a trigger on `auth.users` links the account to the identity and the grant takes effect.

> **Accounts created before the kit was installed.** The trigger fires only when an account is created, or its email changes or is confirmed. A person who was already signed up and confirmed before you installed the kit won't be linked automatically, and `provision_admin` alone won't link them. Run `select authz.reclaim_identity('you@example.com');` after `provision_admin` to link the existing account.

`provision_admin` has no authorization check of its own, so it can't be called through the adapters and isn't exposed to any API role.

## The model

### Inheritance and `inherit = false`

A tenant can opt out of inheritance by setting `inherit = false`. Such a tenant sees only the roles, scopes and bindings defined on itself. The ones defined above it are *filtered out*, except roles marked `crosses_boundary`, which pass through any number of cuts.

Consider the chain Master → A → B → C, where `B.inherit = false` and C inherits normally:

- C sees its own and B's roles, scopes and bindings, but none of A's or Master's ordinary ones. C inherits from B, and B has cut itself off from everything above it.
- A role marked `crosses_boundary` at Master still reaches B and C. Master's built-in `admin` role does this, which is why the platform operator can never be locked out of a tenant.

Only roles can cross a boundary. To make a scope reach past a cut, attach it to a crossing role.

### Shadowing

A tenant can define a role or scope with the same name as an inherited one. Name lookups at and below that tenant then find the nearer definition. **Shadowing never changes an existing grant.** A binding points at a specific role row, so a binding to Master's `admin` keeps Master's scopes everywhere it reaches, even inside a tenant that defines its own `admin`.

### Built-ins

The bootstrap migration seeds the following rows. Built-in IDs share the `a0000000-0000-4000-8000-…` prefix so they're recognisable.

| Row | ID | Notes |
| --- | --- | --- |
| Master tenant | `a0000000-0000-4000-8000-000000000001` | On a fresh database. If a root tenant already exists, the bootstrap keeps it |
| `admin` role | `a0000000-0000-4000-8000-000000000002` | All 14 scopes, `crosses_boundary = true`. The platform operator |
| `tenant_admin` role | `a0000000-0000-4000-8000-000000000003` | Every scope except `authz.users.write`, `crosses_boundary = false`. The owner of a workspace |

The 14 built-in scopes are `authz.<resource>.<action>`:

| Resource | Scopes |
| --- | --- |
| `tenants` | `read`, `write` |
| `users` | `read`, `write` |
| `roles` | `read`, `write` |
| `scopes` | `read`, `write` |
| `bindings` | `read`, `grant`, `revoke` |
| `api_keys` | `read`, `write` |
| `audit` | `read` |

The `authz.` prefix is reserved to the master tenant. Define your application's own scopes under any other name, for example `invoices.read`.

Two of these scopes behave differently from what their names might suggest:

- **`authz.users.write` is platform-wide.** It controls disabling and deleting a person across every tenant. It isn't needed to add, invite or remove someone from a tenant: those are `authz.bindings.grant` and `authz.bindings.revoke`.
- **`authz.roles.write` is the most powerful scope.** Adding a scope to a role widens every existing binding to that role, including bindings issued further up the tree. Keep it out of roles you delegate.

### Rules the write functions enforce

Every mutating function takes the acting principal as its first argument and refuses anything that principal can't do:

- **You can't grant what you don't hold.** Granting a role requires already holding every scope it confers, at that tenant. The same applies to attaching a scope to a role.
- **Only the master tenant's administrators can make a role cross boundaries.** This applies in both directions: turning `crosses_boundary` on, and turning it off.
- **Only the master tenant's administrators can create `authz.`-prefixed scopes.**
- **Changing a tenant's `inherit` flag requires authority at its parent.** That way nobody can cut a tenant off from the oversight above it and keep their own access. A parent admin who cuts off a child can always undo it.
- **API keys can't create API keys.** A person must always be involved in issuing key material.
- **Grants and revocations are soft.** Revoking sets a timestamp and nothing is deleted, so the history stays auditable. Granting a revoked role again reinstates it.

## Access posture

The `authz` schema is private by design:

- It's absent from the PostgREST `[api] schemas`, so nothing in it is reachable through the Supabase REST or GraphQL APIs.
- Nothing is granted to `anon` or `authenticated`, and `PUBLIC EXECUTE` is revoked from every function.
- Row-level security is enabled on every table, with read-only policies. Those policies are defence in depth: no role they govern can currently reach the tables.

Your server reaches the schema through an adapter, on a direct Postgres connection as the `postgres` role. That connection bypasses row-level security, so the SQL functions are what enforce the rules. **Don't write to `authz` tables directly.** Go through the functions, which the adapters expose as a typed write API. Don't add `authz` to your exposed API schemas or grant it to API roles either: that is a different security posture, and the kit isn't built for it yet.

## SQL function reference

Reads. These are the building blocks the adapters use, and you can call them yourself from a `postgres` connection:

| Function | Returns |
| --- | --- |
| `authz.has_scope(principal, tenant, scope)` | Whether the principal holds the scope at the tenant |
| `authz.effective_scopes(principal, tenant)` | Every scope name the principal holds there |
| `authz.effective_bindings(principal, tenant)` | The live bindings that apply there, wherever they were issued |
| `authz.effective_roles(tenant)` | The role definitions visible at the tenant, after shadowing |
| `authz.effective_scope_defs(tenant)` | The scope definitions visible at the tenant |
| `authz.tenant_chain(tenant)` | The ancestor chain, with a flag marking rows beyond a cut |
| `authz.master_tenant_id()` | The master tenant, or null if the bootstrap hasn't run |
| `authz.principal_for_auth_user(auth_user_id)` | The principal behind a Supabase user id |

Writes. Each function takes the acting principal first, and the adapters bind it for you:

| Function | Does |
| --- | --- |
| `grant_role(actor, principal, role, tenant, expires_at)` | Grants a role. This is the only way to grant to an API key |
| `invite_user(actor, tenant, email, role)` | Grants a role to an address, creating an identity if needed |
| `revoke_binding(actor, binding)` | Revokes a grant |
| `create_role(actor, tenant, name, description, crosses_boundary)` | Defines a role |
| `update_role(actor, role, name, description, crosses_boundary)` | Amends a role. A null argument leaves that column unchanged |
| `add_role_scope(actor, role, scope)` / `remove_role_scope(actor, role, scope)` | Attaches a scope to a role, or detaches it |
| `create_scope(actor, tenant, name, description)` | Defines a scope |
| `create_tenant(actor, parent, name)` | Creates a sub-tenant. It grants nothing: the creator's binding already reaches the new tenant |
| `create_workspace(actor, name)` | Creates a child of the master and grants the actor `tenant_admin` there |
| `update_tenant(actor, tenant, name, inherit)` | Renames a tenant or changes its `inherit` flag |
| `create_api_key(actor, tenant, label, expires_at)` | Issues a key. The plaintext is returned **once**, and only its hash is stored |
| `revoke_api_key(actor, key)` | Revokes a key and everything its principal held |

`create_workspace` is the only write with no scope check. It requires only an active principal, so anyone who has signed up can call it. Decide whether to expose it for open signup, gate it behind a plan or an invite, or leave it to an operator. Rate limiting it is up to you.

Operator tools. Run these from the SQL editor only; the adapters never expose them:

| Function | Does |
| --- | --- |
| `provision_admin(email)` | Grants master `admin` to an address. This is the bootstrap step |
| `reclaim_identity(email)` | Links an unlinked identity to the confirmed account that now holds its address |

## Identity lifecycle

- **Claiming.** When an address is confirmed, a trigger on `auth.users` links the account to the identity waiting for that address, or creates a new identity with no roles.
- **Deleted accounts.** Deleting a Supabase account unlinks its identity and leaves the bindings and audit trail intact. If someone registers that address again later, they inherit **nothing**: the old identity is retired rather than handed on. They can sign in, but they hold no authorization, and the adapters answer them with 403.
- **Recovering an account.** If an account was deleted and recreated for the *same* person, `authz.reclaim_identity(email)` relinks the retired identity, and its grants take effect again. Confirm who owns the address before running it.

## License

MIT
