-- Row level security policies for @sirhc77/supabase-auth-kit.
--
-- These are DEFENCE IN DEPTH, not the live enforcement path. The kit runs posture A: the
-- authz schema is absent from [api] schemas, nothing is GRANTed to authenticated or anon,
-- and adapters hold a service_role connection which carries BYPASSRLS. So no role that RLS
-- governs can currently reach these tables at all, and every policy here is dormant.
--
-- They exist so the tables are already governed the day someone grants access or exposes the
-- schema, rather than being wide open at that moment. Do not add GRANTs alongside them
-- without deciding to move to posture B -- the absence of grants is what posture A is.
--
-- SELECT ONLY, deliberately. Every guarded write already has a SECURITY DEFINER function in
-- 001 carrying its rules, and those run as the owner and bypass RLS. Writing WITH CHECK
-- clauses too would duplicate each escalation rule in a second place that can drift, and RLS
-- cannot express some of them anyway: WITH CHECK sees only the new row, never the old, so
-- "may set revoked_at and nothing else" is not writable as a policy. With no INSERT, UPDATE
-- or DELETE policy, RLS denies all three by default and the functions are the only way in.
--
-- Policies are `to public` rather than `to authenticated`. Both fail closed, but this way a
-- role that is later granted access is actually governed by the rule rather than blocked
-- outright, and a role with no JWT resolves current_principal_id() to null, which makes
-- has_scope() false and returns nothing.
--
-- current_principal_id() is wrapped in a scalar subselect throughout so the planner hoists it
-- into an InitPlan and evaluates it once per query instead of once per row.

-- Tenants you hold authz.tenants.read at. has_scope walks up from each row, so a binding
-- made at an ancestor covers the whole subtree without enumerating it.
create policy "tenants_select" on "authz"."tenants"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()), "id",
                           'authz.tenants.read'));


-- Yourself always, plus anyone whose bindings put them in a tenant where you hold
-- authz.users.read. Searching by address for an invite never goes through this policy --
-- it happens inside invite_user() -- which is what keeps lookup from becoming enumeration.
create policy "users_select" on "authz"."users"
    for select to public
    using (
        "auth_user_id" = (select auth.uid())
        or authz.can_read_user((select authz.current_principal_id()), "id")
    );


create policy "principals_select" on "authz"."principals"
    for select to public
    using (authz.can_read_principal((select authz.current_principal_id()), "id"));


create policy "roles_select" on "authz"."roles"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()), "tenant_id",
                           'authz.roles.read'));


create policy "scopes_select" on "authz"."scopes"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()), "tenant_id",
                           'authz.scopes.read'));


-- Gated on the owning role's tenant. role_tenant_id returns null for a role that no longer
-- exists, and has_scope(null) is false, so the link disappears with its role.
create policy "role_scopes_select" on "authz"."role_scopes"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()),
                           authz.role_tenant_id("role_id"),
                           'authz.roles.read'));


-- Your own grants are always visible to you, so a person can see what they hold without
-- being an administrator anywhere.
create policy "role_bindings_select" on "authz"."role_bindings"
    for select to public
    using (
        "principal_id" = (select authz.current_principal_id())
        or authz.has_scope((select authz.current_principal_id()), "tenant_id",
                           'authz.bindings.read')
    );


-- key_hash is readable to anyone with api_keys.read. It is a SHA-256 and not the key, but if
-- this schema is ever exposed, prefer a view that omits the column over relying on that.
create policy "api_keys_select" on "authz"."api_keys"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()), "tenant_id",
                           'authz.api_keys.read'));


-- audit_logs.tenant_id is nullable, and a null tenant means a platform-level action. Without
-- the coalesce those rows would be invisible to everyone, since has_scope(null) is false;
-- with it they require audit.read at the master.
create policy "audit_logs_select" on "authz"."audit_logs"
    for select to public
    using (authz.has_scope((select authz.current_principal_id()),
                           coalesce("tenant_id", authz.master_tenant_id()),
                           'authz.audit.read'));
