set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.bindings_in_force(p_tenant_id uuid)
 RETURNS TABLE(binding_id uuid, principal_id uuid, role_id uuid, source_tenant_id uuid, depth integer)
 LANGUAGE sql
 STABLE
AS $function$
-- No name-keyed merge here: bindings never shadow. A principal can hold master's admin and
-- a child's admin at once and both are returned, deduplicated only by binding row.
select rb.id, rb.principal_id, rb.role_id, rb.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.role_bindings rb on rb.tenant_id = c.tenant_id
  join authz.roles r on r.id = rb.role_id
  join authz.principals p on p.id = rb.principal_id
  left join authz.users u on u.id = p.user_id
  left join authz.api_keys k on k.id = p.api_key_id
 where (not c.crossed or r.crosses_boundary)
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

CREATE OR REPLACE FUNCTION authz.get_tenant(p_actor_principal_id uuid, p_tenant_id uuid)
 RETURNS TABLE(tenant_id uuid, parent_id uuid, name text, inherit boolean, created_at timestamp with time zone, updated_at timestamp with time zone)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select t.id, t.parent_id, t.name, t.inherit, t.created_at, t.updated_at
  from authz.tenants t
 where t.id = p_tenant_id
   and authz.has_scope(p_actor_principal_id, t.id, 'authz.tenants.read');
$function$
;

CREATE OR REPLACE FUNCTION authz.list_api_keys(p_actor_principal_id uuid, p_tenant_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(api_key_id uuid, principal_id uuid, key_prefix text, label text, tenant_id uuid, created_by_user_id uuid, last_used_at timestamp with time zone, expires_at timestamp with time zone, revoked_at timestamp with time zone, created_at timestamp with time zone, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select k.id, p.id, k.key_prefix, k.label, k.tenant_id, k.created_by_user_id,
       k.last_used_at, k.expires_at, k.revoked_at, k.created_at,
       k.id::text || k.label
  from authz.api_keys k
  join authz.principals p on p.api_key_id = k.id
 where k.tenant_id = p_tenant_id
   and authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.api_keys.read')
   and (p_after is null
        or (k.label, k.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by k.label, k.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_child_tenants(p_actor_principal_id uuid, p_parent_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(tenant_id uuid, parent_id uuid, name text, inherit boolean, created_at timestamp with time zone, updated_at timestamp with time zone, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select t.id, t.parent_id, t.name, t.inherit, t.created_at, t.updated_at,
       t.id::text || t.name
  from authz.tenants t
 where t.parent_id = p_parent_id
   and case
           when t.inherit
                and (select authz.has_scope(p_actor_principal_id, p_parent_id,
                                            'authz.tenants.read'))
               then true
           else authz.has_scope(p_actor_principal_id, t.id, 'authz.tenants.read')
       end
   and (p_after is null
        or (t.name, t.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by t.name, t.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_principal_bindings(p_actor_principal_id uuid, p_principal_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(binding_id uuid, principal_id uuid, tenant_id uuid, tenant_name text, role_id uuid, role_name text, granted_by_principal_id uuid, granted_at timestamp with time zone, expires_at timestamp with time zone, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
with visible as (
    select rb.id as binding_id, rb.principal_id, rb.tenant_id,
           case
               when p_actor_principal_id = p_principal_id then t.name
               when authz.has_scope(p_actor_principal_id, rb.tenant_id,
                                    'authz.tenants.read') then t.name
           end as tenant_name,
           rb.role_id,
           case
               when p_actor_principal_id = p_principal_id then r.name
               when authz.has_scope(p_actor_principal_id, rb.tenant_id,
                                    'authz.roles.read') then r.name
           end as role_name,
           rb.granted_by_principal_id, rb.granted_at, rb.expires_at
      from authz.role_bindings rb
      join authz.tenants t on t.id = rb.tenant_id
      join authz.roles r on r.id = rb.role_id
     where rb.principal_id = p_principal_id
       and (p_actor_principal_id = p_principal_id
            or authz.has_scope(p_actor_principal_id, rb.tenant_id, 'authz.bindings.read'))
       -- Liveness comes from bindings_in_force rather than being restated. At a binding's own
       -- tenant nothing is crossed, so all that filter leaves is revoked, expired, disabled.
       and exists (
           select 1
             from authz.bindings_in_force(rb.tenant_id) b
            where b.binding_id = rb.id
       )
)
select v.*, v.binding_id::text || coalesce(v.tenant_name, '')
  from visible v
 where p_after is null
    or (coalesce(v.tenant_name, ''), v.binding_id)
       > (substr(p_after, 37), substr(p_after, 1, 36)::uuid)
 order by coalesce(v.tenant_name, ''), v.binding_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_role_scopes(p_actor_principal_id uuid, p_tenant_id uuid, p_role_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(scope_id uuid, name text, description text, source_tenant_id uuid, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select s.id, s.name, s.description, s.tenant_id, s.id::text || s.name
  from authz.role_scopes rs
  join authz.scopes s on s.id = rs.scope_id
 where rs.role_id = p_role_id
   and authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.roles.read')
   and (exists (select 1 from authz.effective_roles(p_tenant_id) er
                 where er.role_id = p_role_id)
        or exists (select 1 from authz.bindings_in_force(p_tenant_id) b
                    where b.role_id = p_role_id))
   and (p_after is null
        or (s.name, s.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by s.name, s.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_roles(p_actor_principal_id uuid, p_tenant_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(role_id uuid, name text, description text, crosses_boundary boolean, source_tenant_id uuid, inherited boolean, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select er.role_id, er.name, r.description, er.crosses_boundary, er.source_tenant_id,
       er.depth > 0, er.role_id::text || er.name
  from authz.effective_roles(p_tenant_id) er
  join authz.roles r on r.id = er.role_id
 where authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.roles.read')
   and (p_after is null
        or (er.name, er.role_id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by er.name, er.role_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_scopes(p_actor_principal_id uuid, p_tenant_id uuid, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(scope_id uuid, name text, description text, source_tenant_id uuid, inherited boolean, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select sd.scope_id, sd.name, s.description, sd.source_tenant_id, sd.depth > 0,
       sd.scope_id::text || sd.name
  from authz.effective_scope_defs(p_tenant_id) sd
  join authz.scopes s on s.id = sd.scope_id
 where authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.scopes.read')
   and (p_after is null
        or (sd.name, sd.scope_id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by sd.name, sd.scope_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.list_tenant_bindings(p_actor_principal_id uuid, p_tenant_id uuid, p_include_inherited boolean DEFAULT false, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(binding_id uuid, principal_id uuid, principal_kind text, user_id uuid, email text, claimed boolean, api_key_id uuid, api_key_label text, role_id uuid, role_name text, source_tenant_id uuid, inherited boolean, granted_by_principal_id uuid, granted_at timestamp with time zone, expires_at timestamp with time zone, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
-- MATERIALIZED is load-bearing. A CTE referenced once is otherwise inlined into the join, and
-- then these has_scope calls run once per binding instead of once per tenant in the chain:
-- measured at 43 seconds for one page of a tenant with 20k members, against milliseconds here.
with sources as materialized (
    select c.tenant_id,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.bindings.read') as bindings_read,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.users.read') as users_read,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.roles.read') as roles_read
      from authz.tenant_chain(p_tenant_id) c
     where c.depth = 0 or coalesce(p_include_inherited, false)
),
visible as (
    select b.binding_id, b.principal_id, p.kind::text as principal_kind,
           p.user_id,
           case when s.users_read or b.principal_id = p_actor_principal_id
                then u.email end as email,
           case when p.kind = 'user' then u.auth_user_id is not null end as claimed,
           p.api_key_id,
           case
               when k.id is null then null
               when authz.has_scope(p_actor_principal_id, k.tenant_id,
                                    'authz.api_keys.read') then k.label
           end as api_key_label,
           b.role_id,
           case when s.roles_read or b.principal_id = p_actor_principal_id
                then r.name end as role_name,
           b.source_tenant_id,
           b.depth > 0 as inherited,
           rb.granted_by_principal_id, rb.granted_at, rb.expires_at
      from authz.bindings_in_force(p_tenant_id) b
      join sources s on s.tenant_id = b.source_tenant_id
      join authz.role_bindings rb on rb.id = b.binding_id
      join authz.roles r on r.id = b.role_id
      join authz.principals p on p.id = b.principal_id
      left join authz.users u on u.id = p.user_id
      left join authz.api_keys k on k.id = p.api_key_id
     where s.bindings_read or b.principal_id = p_actor_principal_id
)
select v.*, v.binding_id::text || coalesce(v.email, v.api_key_label, '')
  from visible v
 where p_after is null
    or (coalesce(v.email, v.api_key_label, ''), v.binding_id)
       > (substr(p_after, 37), substr(p_after, 1, 36)::uuid)
 order by coalesce(v.email, v.api_key_label, ''), v.binding_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.effective_bindings(p_principal_id uuid, p_tenant_id uuid)
 RETURNS TABLE(binding_id uuid, role_id uuid, source_tenant_id uuid, depth integer)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select b.binding_id, b.role_id, b.source_tenant_id, b.depth
  from authz.bindings_in_force(p_tenant_id) b
 where b.principal_id = p_principal_id;
$function$
;



-- Every read here is new, so each arrived with the built-in PUBLIC EXECUTE grant. Taking it
-- off again is a standing obligation of every migration that adds a function to authz; see
-- 20260909060000_auth_kit_privileges.sql. The service_role grants for these functions are
-- made explicitly, per function, in 20260913040000_auth_kit_rpc_privileges.sql.
revoke execute on all functions in schema "authz" from public;
