set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.add_role_scope(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id  uuid;
    v_scope_name text;
begin
    select r.tenant_id into v_tenant_id
      from authz.roles r
     where r.id = p_role_id;

    if v_tenant_id is null then
        raise exception 'role % does not exist', p_role_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, v_tenant_id, 'authz.roles.write') then
        raise exception 'principal % lacks authz.roles.write at tenant %',
            p_actor_principal_id, v_tenant_id;
    end if;

    -- The scope must resolve at the role's own tenant. A shadowed row will not appear here,
    -- which is intended: at that tenant the name means the nearer definition.
    select sd.name into v_scope_name
      from authz.effective_scope_defs(v_tenant_id) sd
     where sd.scope_id = p_scope_id;

    if v_scope_name is null then
        raise exception 'scope % is not visible at tenant %', p_scope_id, v_tenant_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, v_tenant_id, v_scope_name) then
        raise exception
            'principal % cannot attach scope % to role %: does not hold it at tenant %',
            p_actor_principal_id, v_scope_name, p_role_id, v_tenant_id;
    end if;

    insert into authz.role_scopes (role_id, scope_id)
    values (p_role_id, p_scope_id)
    on conflict do nothing;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.remove_role_scope(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id uuid;
begin
    select r.tenant_id into v_tenant_id
      from authz.roles r
     where r.id = p_role_id;

    if v_tenant_id is null then
        raise exception 'role % does not exist', p_role_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, v_tenant_id, 'authz.roles.write') then
        raise exception 'principal % lacks authz.roles.write at tenant %',
            p_actor_principal_id, v_tenant_id;
    end if;

    -- No holds-it check here: detaching narrows every binding to this role, so it cannot
    -- manufacture authority. role_scopes carries no revoked_at, so this is a hard delete --
    -- the one place in the schema where removal is not a timestamp.
    delete from authz.role_scopes rs
     where rs.role_id = p_role_id
       and rs.scope_id = p_scope_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.update_role(p_actor_principal_id uuid, p_role_id uuid, p_name text DEFAULT NULL::text, p_description text DEFAULT NULL::text, p_crosses_boundary boolean DEFAULT NULL::boolean)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id uuid;
    v_current   boolean;
begin
    select r.tenant_id, r.crosses_boundary
      into v_tenant_id, v_current
      from authz.roles r
     where r.id = p_role_id;

    if v_tenant_id is null then
        raise exception 'role % does not exist', p_role_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, v_tenant_id, 'authz.roles.write') then
        raise exception 'principal % lacks authz.roles.write at tenant %',
            p_actor_principal_id, v_tenant_id;
    end if;

    -- Master authority is required to change crossing in *either* direction. Turning it on
    -- manufactures reach the actor does not have; turning it off strips reach the operator
    -- was relying on, so a tenant admin must not be able to un-cross a role the operator
    -- placed in their tenant. Only a change is gated -- passing the current value is a no-op.
    if p_crosses_boundary is not null
       and p_crosses_boundary <> v_current
       and not authz.has_scope(p_actor_principal_id,
                               authz.master_tenant_id(),
                               'authz.roles.write')
    then
        raise exception
            'principal % cannot change crosses_boundary on role %: that requires authz.roles.write at the master tenant',
            p_actor_principal_id, p_role_id;
    end if;

    update authz.roles r
       set name             = coalesce(p_name, r.name),
           description      = coalesce(p_description, r.description),
           crosses_boundary = coalesce(p_crosses_boundary, r.crosses_boundary),
           updated_at       = now()
     where r.id = p_role_id;
end;
$function$
;


