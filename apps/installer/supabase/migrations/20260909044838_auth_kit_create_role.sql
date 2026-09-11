set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.create_role(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text, p_crosses_boundary boolean DEFAULT false)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_role_id uuid := gen_random_uuid();
begin
    if not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.roles.write') then
        raise exception 'principal % lacks authz.roles.write at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    if coalesce(p_crosses_boundary, false)
       and not authz.has_scope(p_actor_principal_id,
                               authz.master_tenant_id(),
                               'authz.roles.write')
    then
        raise exception
            'principal % cannot create a crosses_boundary role at tenant %: that requires authz.roles.write at the master tenant',
            p_actor_principal_id, p_tenant_id;
    end if;

    insert into authz.roles (id, tenant_id, name, description, crosses_boundary)
    values (v_role_id, p_tenant_id, p_name, p_description,
            coalesce(p_crosses_boundary, false));

    return v_role_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.master_tenant_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select t.id from authz.tenants t where t.parent_id is null;
$function$
;


