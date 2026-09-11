set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.current_principal_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select p.id
  from authz.users u
  join authz.principals p on p.user_id = u.id
 where u.auth_user_id = (select auth.uid())
   and u.disabled_at is null
   and u.deleted_at is null;
$function$
;

CREATE OR REPLACE FUNCTION authz.effective_bindings(p_principal_id uuid, p_tenant_id uuid)
 RETURNS TABLE(binding_id uuid, role_id uuid, source_tenant_id uuid, depth integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
-- No name-keyed merge here: bindings never shadow. A principal can hold master's admin and
-- a child's admin at once and both are returned, deduplicated only by binding row.
select rb.id, rb.role_id, rb.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.role_bindings rb on rb.tenant_id = c.tenant_id
  join authz.roles r on r.id = rb.role_id
  join authz.principals p on p.id = rb.principal_id
  left join authz.users u on u.id = p.user_id
  left join authz.api_keys k on k.id = p.api_key_id
 where rb.principal_id = p_principal_id
   and (not c.crossed or r.crosses_boundary)
   -- Soft deletion is never implicit: every revocable timestamp is filtered here, because
   -- this is the one place grants are read.
   and rb.revoked_at is null
   and (rb.expires_at is null or rb.expires_at > now())
   -- An unclaimed identity is deliberately NOT excluded: it is unreachable from a JWT
   -- anyway, and an admin view asking what a provisioned identity will hold should see it.
   -- disabled_at and deleted_at are different -- those are revocations, so they do exclude.
   and (p.kind <> 'user'
        or (u.disabled_at is null and u.deleted_at is null))
   and (p.kind <> 'api_key'
        or (k.revoked_at is null
            and (k.expires_at is null or k.expires_at > now())));
$function$
;

CREATE OR REPLACE FUNCTION authz.effective_roles(p_tenant_id uuid)
 RETURNS TABLE(role_id uuid, name text, crosses_boundary boolean, source_tenant_id uuid, depth integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
-- distinct on (name) ordered by depth is the left-biased merge: the closest definition of
-- each name survives and shadows the inherited one.
select distinct on (r.name)
       r.id, r.name, r.crosses_boundary, r.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.roles r on r.tenant_id = c.tenant_id
 where not c.crossed or r.crosses_boundary
 order by r.name, c.depth;
$function$
;

CREATE OR REPLACE FUNCTION authz.effective_scope_defs(p_tenant_id uuid)
 RETURNS TABLE(scope_id uuid, name text, source_tenant_id uuid, depth integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
-- scopes has no crosses_boundary of its own, so past a cut a scope is visible only by
-- hanging off a crossing role through role_scopes.
select distinct on (s.name)
       s.id, s.name, s.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.scopes s on s.tenant_id = c.tenant_id
 where not c.crossed
    or exists (
        select 1
          from authz.role_scopes rs
          join authz.roles r on r.id = rs.role_id
         where rs.scope_id = s.id
           and r.crosses_boundary
       )
 order by s.name, c.depth;
$function$
;

CREATE OR REPLACE FUNCTION authz.effective_scopes(p_principal_id uuid, p_tenant_id uuid)
 RETURNS TABLE(scope_name text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
-- Scopes come from each binding's own role_id through role_scopes -- never from whatever
-- effective_roles() resolves that role's name to at this tenant. A child defining a role
-- of the same name does not change what an already-issued grant confers.
select distinct s.name
  from authz.effective_bindings(p_principal_id, p_tenant_id) b
  join authz.role_scopes rs on rs.role_id = b.role_id
  join authz.scopes s on s.id = rs.scope_id;
$function$
;

CREATE OR REPLACE FUNCTION authz.has_scope(p_principal_id uuid, p_tenant_id uuid, p_scope text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select exists (
    select 1
      from authz.effective_scopes(p_principal_id, p_tenant_id) es
     where es.scope_name = p_scope
);
$function$
;

CREATE OR REPLACE FUNCTION authz.tenant_chain(p_tenant_id uuid)
 RETURNS TABLE(tenant_id uuid, crossed boolean, depth integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
with recursive chain as (
    select t.id, t.parent_id, t.inherit, false as crossed_flag, 0 as lvl
      from authz.tenants t
     where t.id = p_tenant_id
    union all
    -- The depth cap is a guard, not a limit: tenants is a tree, but parent_id is only a
    -- self-FK and nothing forbids a cycle, which would otherwise spin forever.
    select p.id, p.parent_id, p.inherit, c.crossed_flag or not c.inherit, c.lvl + 1
      from chain c
      join authz.tenants p on p.id = c.parent_id
     where c.lvl < 64
)
select c.id, c.crossed_flag, c.lvl from chain c;
$function$
;


