set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.can_read_principal(p_actor_principal_id uuid, p_principal_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select exists (
    select 1
      from authz.principals p
      left join authz.api_keys k on k.id = p.api_key_id
     where p.id = p_principal_id
       and (p.id = p_actor_principal_id
            or (p.user_id is not null
                and authz.can_read_user(p_actor_principal_id, p.user_id))
            or (k.id is not null
                and authz.has_scope(p_actor_principal_id, k.tenant_id,
                                    'authz.api_keys.read')))
);
$function$
;

CREATE OR REPLACE FUNCTION authz.can_read_user(p_actor_principal_id uuid, p_user_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select exists (
    select 1
      from authz.role_bindings rb
      join authz.principals p on p.id = rb.principal_id
     where p.user_id = p_user_id
       and rb.revoked_at is null
       and (rb.expires_at is null or rb.expires_at > now())
       and authz.has_scope(p_actor_principal_id, rb.tenant_id, 'authz.users.read')
);
$function$
;

CREATE OR REPLACE FUNCTION authz.role_tenant_id(p_role_id uuid)
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select r.tenant_id from authz.roles r where r.id = p_role_id;
$function$
;


  create policy "api_keys_select"
  on "authz"."api_keys"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), tenant_id, 'authz.api_keys.read'::text));



  create policy "audit_logs_select"
  on "authz"."audit_logs"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), COALESCE(tenant_id, authz.master_tenant_id()), 'authz.audit.read'::text));



  create policy "principals_select"
  on "authz"."principals"
  as permissive
  for select
  to public
using (authz.can_read_principal(( SELECT authz.current_principal_id() AS current_principal_id), id));



  create policy "role_bindings_select"
  on "authz"."role_bindings"
  as permissive
  for select
  to public
using (((principal_id = ( SELECT authz.current_principal_id() AS current_principal_id)) OR authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), tenant_id, 'authz.bindings.read'::text)));



  create policy "role_scopes_select"
  on "authz"."role_scopes"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), authz.role_tenant_id(role_id), 'authz.roles.read'::text));



  create policy "roles_select"
  on "authz"."roles"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), tenant_id, 'authz.roles.read'::text));



  create policy "scopes_select"
  on "authz"."scopes"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), tenant_id, 'authz.scopes.read'::text));



  create policy "tenants_select"
  on "authz"."tenants"
  as permissive
  for select
  to public
using (authz.has_scope(( SELECT authz.current_principal_id() AS current_principal_id), id, 'authz.tenants.read'::text));



  create policy "users_select"
  on "authz"."users"
  as permissive
  for select
  to public
using (((auth_user_id = ( SELECT auth.uid() AS uid)) OR authz.can_read_user(( SELECT authz.current_principal_id() AS current_principal_id), id)));



