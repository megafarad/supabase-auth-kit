---
"@sirhc77/supabase-auth-kit-core": minor
"@sirhc77/supabase-auth-kit-express": minor
"@sirhc77/supabase-auth-kit-fastify": minor
---

Add `requireIdentity` to both adapters, over a new `enforceIdentity` in core.

It requires a principal without asking what they may do — 401 without a credential, 403 for a credential that maps to no authz identity — with no tenant, no scope and no database round trip. It is the guard for the routes whose authority the request cannot name: `createWorkspace` needs no scope at any tenant, and `revokeBinding`, `updateRole`, `addRoleScope`, `removeRoleScope` and `revokeApiKey` are governed by the tenant on the row being changed, which only SQL can read. On a route with no tenant in it, `requireScope` answers 400 to every request, so those routes previously had no guard the kit could supply.

`enforceGuard` now calls `enforceIdentity` for its first two branches, so the 401/403 split and the denied audit row it records are shared rather than restated.

Not a substitute for a scope check on a read: reads refuse by filtering, so `requireIdentity` on a list route answers `200 []` where `requireScope` answers 403.
