-- Bootstrap data for @sirhc77/supabase-auth-kit.
--
-- Hand-written on purpose. `supabase db diff` compares structure, not data, so the rows
-- the authorization model requires cannot come out of `schemas/`. This is the documented
-- exception to "migrations are generated, never hand-written" -- do not try to regenerate
-- this file, and keep it sorting after the schema migration so the tables exist first.
--
-- Built-in identifiers live under the reserved a0000000-0000-4000-8000-... prefix.
--
-- Idempotent throughout: every insert is ON CONFLICT DO NOTHING, and the master tenant is
-- resolved rather than assumed, so a database that already has a root tenant keeps its own.

do $$
declare
    master_id       uuid;
    admin_id        uuid := 'a0000000-0000-4000-8000-000000000002';
    tenant_admin_id uuid := 'a0000000-0000-4000-8000-000000000003';
begin
    -- Exactly one master tenant. tenants_single_master_uq caps it at one; this supplies the one.
    insert into authz.tenants (id, parent_id, name)
    values ('a0000000-0000-4000-8000-000000000001', null, 'master')
    on conflict do nothing;

    -- STRICT: fail loudly if the invariant does not hold rather than bootstrapping into a
    -- database with no root, which would leave the resolution recurrence without a base case.
    select id into strict master_id from authz.tenants where parent_id is null;

    insert into authz.scopes (id, tenant_id, name, description) values
        ('a0000000-0000-4000-8000-000000000101', master_id, 'authz.tenants.read',     'Read tenants and the tenant tree'),
        ('a0000000-0000-4000-8000-000000000102', master_id, 'authz.tenants.write',    'Create and modify tenants'),
        ('a0000000-0000-4000-8000-000000000103', master_id, 'authz.users.read',       'Read authz user records'),
        ('a0000000-0000-4000-8000-000000000104', master_id, 'authz.users.write',      'Create, disable, and modify authz user records'),
        ('a0000000-0000-4000-8000-000000000105', master_id, 'authz.roles.read',       'Read role definitions and their scopes'),
        -- Escalation-capable: role_scopes is keyed by id and bindings point at role rows, so
        -- editing a role silently widens every existing binding to it, including ones issued
        -- at master and propagated down. Keep this out of any delegated tenant-admin role.
        ('a0000000-0000-4000-8000-000000000106', master_id, 'authz.roles.write',      'Create and modify roles and their scope assignments'),
        ('a0000000-0000-4000-8000-000000000107', master_id, 'authz.scopes.read',      'Read scope definitions'),
        ('a0000000-0000-4000-8000-000000000108', master_id, 'authz.scopes.write',     'Create and modify scope definitions'),
        ('a0000000-0000-4000-8000-000000000109', master_id, 'authz.bindings.read',    'Read role bindings'),
        -- Granting is escalation, revoking is de-escalation. Split so that revoke can be
        -- delegated to support or incident response without also delegating grant.
        ('a0000000-0000-4000-8000-00000000010a', master_id, 'authz.bindings.grant',   'Grant roles to principals'),
        ('a0000000-0000-4000-8000-00000000010b', master_id, 'authz.bindings.revoke',  'Revoke existing role bindings'),
        ('a0000000-0000-4000-8000-00000000010c', master_id, 'authz.api_keys.read',    'Read API key metadata'),
        ('a0000000-0000-4000-8000-00000000010d', master_id, 'authz.api_keys.write',   'Issue and revoke API keys'),
        -- Read-only by design: nothing should write audit rows through a role.
        ('a0000000-0000-4000-8000-00000000010e', master_id, 'authz.audit.read',       'Read the audit log')
    on conflict do nothing;

    -- crosses_boundary = true is load-bearing. Without it, a tenant setting inherit = false
    -- cuts off this role's definition *and* every propagated binding to it, locking the
    -- platform operator out of a tenant that tenant administers.
    insert into authz.roles (id, tenant_id, name, description, crosses_boundary)
    values (admin_id, master_id, 'admin', 'Full administration of the authz schema', true)
    on conflict do nothing;

    -- Selected rather than enumerated so the role stays in sync if scopes are added above.
    insert into authz.role_scopes (role_id, scope_id)
    select admin_id, s.id
    from authz.scopes s
    where s.tenant_id = master_id
      and s.name like 'authz.%'
    on conflict do nothing;

    -- The role a workspace owner holds at their own tenant, as distinct from the platform
    -- operator's. crosses_boundary is false: the less powerful default, and its failure mode
    -- is the recoverable one. If a sub-tenant sets inherit = false its parent's tenant_admins
    -- lose reach into it, which is visible and fixable -- 'admin' does cross, so the operator
    -- can always intervene. Flipping this to true instead would silently deny sub-tenants any
    -- isolation from the tenants above them.
    insert into authz.roles (id, tenant_id, name, description, crosses_boundary)
    values (tenant_admin_id, master_id, 'tenant_admin',
            'Administration of a single tenant and its subtree', false)
    on conflict do nothing;

    -- Everything except authz.users.write. Membership is expressed through role_bindings, so
    -- adding, inviting and removing people is bindings.grant/revoke and needs nothing from
    -- this exclusion. authz.users.write is the *global* person lifecycle -- disabled_at and
    -- deleted_at apply across every tenant at once, so one tenant's admin must not hold it.
    insert into authz.role_scopes (role_id, scope_id)
    select tenant_admin_id, s.id
    from authz.scopes s
    where s.tenant_id = master_id
      and s.name like 'authz.%'
      and s.name <> 'authz.users.write'
    on conflict do nothing;
end
$$;
