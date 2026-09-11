set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.revoke_binding(p_actor_principal_id uuid, p_binding_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id  uuid;
    v_revoked_at timestamptz;
    v_found      boolean;
begin
    select true, rb.tenant_id, rb.revoked_at
      into v_found, v_tenant_id, v_revoked_at
      from authz.role_bindings rb
     where rb.id = p_binding_id;

    if not coalesce(v_found, false) then
        raise exception 'binding % does not exist', p_binding_id;
    end if;

    -- Anchored on the binding's own tenant, so revoking a grant issued higher up the tree
    -- requires authority there -- a tenant admin cannot reach a binding made at the master.
    if not authz.has_scope(p_actor_principal_id, v_tenant_id, 'authz.bindings.revoke') then
        raise exception 'principal % lacks authz.bindings.revoke at tenant %',
            p_actor_principal_id, v_tenant_id;
    end if;

    -- No holds-it check, unlike granting: revocation only ever narrows.
    if v_revoked_at is null then
        update authz.role_bindings rb
           set revoked_at = now(),
               updated_at = now()
         where rb.id = p_binding_id;
    end if;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.update_tenant(p_actor_principal_id uuid, p_tenant_id uuid, p_name text DEFAULT NULL::text, p_inherit boolean DEFAULT NULL::boolean)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_parent_id uuid;
    v_current   boolean;
    v_found     boolean;
begin
    select true, t.parent_id, t.inherit
      into v_found, v_parent_id, v_current
      from authz.tenants t
     where t.id = p_tenant_id;

    if not coalesce(v_found, false) then
        raise exception 'tenant % does not exist', p_tenant_id;
    end if;

    if p_name is not null
       and not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.tenants.write')
    then
        raise exception 'principal % lacks authz.tenants.write at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    if p_inherit is not null and p_inherit <> v_current then
        if v_parent_id is null then
            raise exception
                'tenant % is the master and has no parent to inherit from', p_tenant_id;
        end if;

        if not authz.has_scope(p_actor_principal_id, v_parent_id,
                               'authz.tenants.write') then
            raise exception
                'principal % cannot change inherit on tenant %: that requires authz.tenants.write at its parent %',
                p_actor_principal_id, p_tenant_id, v_parent_id;
        end if;
    end if;

    update authz.tenants t
       set name       = coalesce(p_name, t.name),
           inherit    = coalesce(p_inherit, t.inherit),
           updated_at = now()
     where t.id = p_tenant_id;
end;
$function$
;


