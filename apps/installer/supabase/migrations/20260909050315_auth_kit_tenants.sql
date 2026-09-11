set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.create_tenant(p_actor_principal_id uuid, p_parent_id uuid, p_name text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id uuid := gen_random_uuid();
begin
    if not exists (select 1 from authz.tenants t where t.id = p_parent_id) then
        raise exception 'parent tenant % does not exist', p_parent_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, p_parent_id, 'authz.tenants.write') then
        raise exception 'principal % lacks authz.tenants.write at tenant %',
            p_actor_principal_id, p_parent_id;
    end if;

    insert into authz.tenants (id, parent_id, name)
    values (v_tenant_id, p_parent_id, p_name);

    return v_tenant_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_workspace(p_actor_principal_id uuid, p_name text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_master_id       uuid;
    v_tenant_admin_id uuid;
    v_tenant_id       uuid := gen_random_uuid();
begin
    if not authz.principal_is_active(p_actor_principal_id) then
        raise exception
            'principal % cannot create a workspace: not a claimed, active principal',
            p_actor_principal_id;
    end if;

    -- STRICT on both: a database whose bootstrap has not run should fail loudly rather than
    -- produce a workspace nobody administers.
    select t.id into strict v_master_id
      from authz.tenants t
     where t.parent_id is null;

    select r.id into strict v_tenant_admin_id
      from authz.roles r
     where r.tenant_id = v_master_id
       and r.name = 'tenant_admin';

    insert into authz.tenants (id, parent_id, name)
    values (v_tenant_id, v_master_id, p_name);

    -- Self-granted, like provision_admin's. There is no earlier principal to name as the
    -- granter, and principals_exactly_one_of forbids inventing a system one.
    insert into authz.role_bindings (
        id, principal_id, role_id, tenant_id, granted_by_principal_id
    )
    values (
        gen_random_uuid(), p_actor_principal_id, v_tenant_admin_id, v_tenant_id,
        p_actor_principal_id
    );

    return v_tenant_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.principal_is_active(p_principal_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select exists (
    select 1
      from authz.principals p
      left join authz.users u on u.id = p.user_id
      left join authz.api_keys k on k.id = p.api_key_id
     where p.id = p_principal_id
       and (p.kind <> 'user'
            or (u.auth_user_id is not null
                and u.disabled_at is null
                and u.deleted_at is null))
       and (p.kind <> 'api_key'
            or (k.revoked_at is null
                and (k.expires_at is null or k.expires_at > now())))
);
$function$
;


