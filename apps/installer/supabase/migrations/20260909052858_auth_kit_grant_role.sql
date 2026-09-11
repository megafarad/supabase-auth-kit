set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.grant_role(p_actor_principal_id uuid, p_principal_id uuid, p_role_id uuid, p_tenant_id uuid, p_expires_at timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_binding_id   uuid;
    v_missing      text;
    v_kind         authz.principal_kind;
    v_claimed_at   timestamptz;
    v_auth_user_id uuid;
begin
    select p.kind, u.claimed_at, u.auth_user_id
      into v_kind, v_claimed_at, v_auth_user_id
      from authz.principals p
      left join authz.users u on u.id = p.user_id
     where p.id = p_principal_id;

    if v_kind is null then
        raise exception 'principal % does not exist', p_principal_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.bindings.grant') then
        raise exception 'principal % lacks authz.bindings.grant at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    -- The role has to resolve at this tenant. Without this a caller could bind a role owned
    -- by an unrelated branch of the tree, which the tenant cannot even see.
    if not exists (
        select 1 from authz.effective_roles(p_tenant_id) er
         where er.role_id = p_role_id
    ) then
        raise exception 'role % is not visible at tenant %', p_role_id, p_tenant_id;
    end if;

    -- You cannot grant what you do not hold. Without this, authz.bindings.grant alone would
    -- be equivalent to full administration: bind yourself to 'admin' and take all 14 scopes.
    select string_agg(s.name, ', ' order by s.name) into v_missing
      from authz.role_scopes rs
      join authz.scopes s on s.id = rs.scope_id
     where rs.role_id = p_role_id
       and not authz.has_scope(p_actor_principal_id, p_tenant_id, s.name);

    if v_missing is not null then
        raise exception 'principal % cannot grant role %: does not hold %',
            p_actor_principal_id, p_role_id, v_missing;
    end if;

    -- Backstop for direct callers. invite_user catches this earlier, where it still has the
    -- address in hand and can say which one.
    if v_kind = 'user' and v_claimed_at is not null and v_auth_user_id is null then
        raise exception
            'principal % belongs to a retired identity; authz.reclaim_identity() first',
            p_principal_id;
    end if;

    -- Upsert, not on-conflict-do-nothing. (principal_id, role_id, tenant_id) is unique
    -- whether or not the binding is revoked, so do-nothing would make re-granting a
    -- previously revoked role a silent no-op: the caller would believe access was restored
    -- when it was not. Re-granting is a new grant, so granted_at and granted_by move too.
    insert into authz.role_bindings (
        id, principal_id, role_id, tenant_id, granted_by_principal_id, expires_at
    )
    values (
        gen_random_uuid(), p_principal_id, p_role_id, p_tenant_id,
        p_actor_principal_id, p_expires_at
    )
    on conflict (principal_id, role_id, tenant_id) do update
       set revoked_at              = null,
           granted_at              = now(),
           granted_by_principal_id = p_actor_principal_id,
           expires_at              = p_expires_at,
           updated_at              = now()
    returning id into v_binding_id;

    return v_binding_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.invite_user(p_actor_principal_id uuid, p_tenant_id uuid, p_email text, p_role_id uuid)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_user_id      uuid;
    v_principal_id uuid;
    v_claimed_at   timestamptz;
    v_auth_user_id uuid;
begin
    -- Pre-flight, even though grant_role checks this again and is authoritative. It has to
    -- come before the identity lookup below: the retired-identity error names an address, so
    -- checking authority afterwards would let an unauthorised caller probe which addresses
    -- have retired identities. It also avoids creating an identity that the grant then rolls
    -- back. has_scope already excludes disabled, deleted, revoked and expired grants.
    if not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.bindings.grant') then
        raise exception 'principal % lacks authz.bindings.grant at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    select u.id, u.claimed_at, u.auth_user_id
      into v_user_id, v_claimed_at, v_auth_user_id
      from authz.users u
     where u.email_id = authz.email_id(p_email);

    if v_user_id is null then
        v_user_id := gen_random_uuid();

        insert into authz.users (id, auth_user_id, email_id, email)
        values (v_user_id, null, authz.email_id(p_email), p_email);
    elsif v_claimed_at is not null and v_auth_user_id is null then
        -- Retired identity. claim_auth_user() will not hand it to a new signup, so a binding
        -- added here could never be exercised -- fail loudly instead of inviting into a dead
        -- end that looks like it worked.
        raise exception
            'identity for % is retired; authz.reclaim_identity() first if it is the same person',
            p_email;
    end if;

    select p.id into v_principal_id
      from authz.principals p
     where p.user_id = v_user_id;

    if v_principal_id is null then
        v_principal_id := gen_random_uuid();

        insert into authz.principals (id, kind, user_id)
        values (v_principal_id, 'user', v_user_id);
    end if;

    -- Everything from here is generic, so it lives in grant_role: authority, role
    -- visibility, the holds-it rule, and reinstating a revoked binding.
    perform authz.grant_role(p_actor_principal_id, v_principal_id, p_role_id, p_tenant_id);

    return v_user_id;
end;
$function$
;


