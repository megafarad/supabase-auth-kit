set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.create_api_key(p_actor_principal_id uuid, p_tenant_id uuid, p_label text, p_expires_at timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_user_id uuid;
    v_key_id  uuid := gen_random_uuid();
    v_prefix  text;
    v_key     text;
begin
    if not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.api_keys.write') then
        raise exception 'principal % lacks authz.api_keys.write at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    -- created_by_user_id is NOT NULL and an api_key principal has no user behind it, so a
    -- key cannot mint another key. That is a useful ceiling rather than an inconvenience:
    -- key material never begets more key material without a person in the loop.
    select p.user_id into v_user_id
      from authz.principals p
     where p.id = p_actor_principal_id;

    if v_user_id is null then
        raise exception
            'principal % is not a user principal; only a user can issue an API key',
            p_actor_principal_id;
    end if;

    -- gen_random_uuid() draws on the same CSPRNG pgcrypto would, so no extension is needed.
    -- The prefix is the lookup key (unique, indexed); the secret is what the hash covers.
    v_prefix := replace(gen_random_uuid()::text, '-', '');
    v_key := 'sak_' || v_prefix || '_'
          || replace(gen_random_uuid()::text, '-', '')
          || replace(gen_random_uuid()::text, '-', '');

    insert into authz.api_keys (id, key_hash, key_prefix, label, tenant_id,
                                created_by_user_id, expires_at)
    values (v_key_id,
            encode(sha256(v_key::bytea), 'hex')::char(64),
            v_prefix, p_label, p_tenant_id, v_user_id, p_expires_at);

    insert into authz.principals (id, kind, api_key_id)
    values (gen_random_uuid(), 'api_key', v_key_id);

    return v_key;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_scope(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text DEFAULT NULL::text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_scope_id uuid := gen_random_uuid();
begin
    if not authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.scopes.write') then
        raise exception 'principal % lacks authz.scopes.write at tenant %',
            p_actor_principal_id, p_tenant_id;
    end if;

    if p_name like 'authz.%'
       and not authz.has_scope(p_actor_principal_id,
                               authz.master_tenant_id(),
                               'authz.scopes.write')
    then
        raise exception
            'principal % cannot define % in the reserved authz. namespace: that requires authz.scopes.write at the master tenant',
            p_actor_principal_id, p_name;
    end if;

    insert into authz.scopes (id, tenant_id, name, description)
    values (v_scope_id, p_tenant_id, p_name, p_description);

    return v_scope_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.revoke_api_key(p_actor_principal_id uuid, p_api_key_id uuid)
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
    select true, k.tenant_id, k.revoked_at
      into v_found, v_tenant_id, v_revoked_at
      from authz.api_keys k
     where k.id = p_api_key_id;

    if not coalesce(v_found, false) then
        raise exception 'api key % does not exist', p_api_key_id;
    end if;

    if not authz.has_scope(p_actor_principal_id, v_tenant_id, 'authz.api_keys.write') then
        raise exception 'principal % lacks authz.api_keys.write at tenant %',
            p_actor_principal_id, v_tenant_id;
    end if;

    if v_revoked_at is null then
        update authz.api_keys k
           set revoked_at = now(),
               updated_at = now()
         where k.id = p_api_key_id;
    end if;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.verify_api_key(p_key text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_prefix       text;
    v_key_id       uuid;
    v_principal_id uuid;
begin
    -- sak_<prefix>_<secret>
    v_prefix := split_part(p_key, '_', 2);

    if v_prefix is null or v_prefix = '' then
        return null;
    end if;

    -- The unique prefix index does the discrimination, so the hash comparison runs against
    -- at most one row. It is not constant-time, but an attacker must already know a valid
    -- prefix to reach it.
    select k.id into v_key_id
      from authz.api_keys k
     where k.key_prefix = v_prefix
       and k.key_hash = encode(sha256(p_key::bytea), 'hex')::char(64)
       and k.revoked_at is null
       and (k.expires_at is null or k.expires_at > now());

    if v_key_id is null then
        -- Null for unknown, wrong, revoked and expired alike: fail closed, and say nothing
        -- about which.
        return null;
    end if;

    -- One row-level write per authenticated request. If that becomes contention on a hot
    -- key, this is the line to make conditional or move off the request path.
    update authz.api_keys k
       set last_used_at = now(),
           updated_at   = now()
     where k.id = v_key_id;

    select p.id into v_principal_id
      from authz.principals p
     where p.api_key_id = v_key_id;

    return v_principal_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.add_role_scope(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id       uuid;
    v_scope_name      text;
    v_scope_tenant_id uuid;
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
    select sd.name, sd.source_tenant_id
      into v_scope_name, v_scope_tenant_id
      from authz.effective_scope_defs(v_tenant_id) sd
     where sd.scope_id = p_scope_id;

    if v_scope_name is null then
        raise exception 'scope % is not visible at tenant %', p_scope_id, v_tenant_id;
    end if;

    -- Either the actor already holds the scope, or they are the authority over its
    -- definition. That second clause is what makes create_scope usable at all: a freshly
    -- defined scope is held by nobody, so a holds-it check on its own would leave every new
    -- scope permanently unattachable -- by anyone, including the operator.
    --
    -- It cannot be turned on the built-ins, because the authz. namespace is reserved to the
    -- master (see create_scope) and a tenant admin holds no authz.scopes.write there.
    if not authz.has_scope(p_actor_principal_id, v_tenant_id, v_scope_name)
       and not authz.has_scope(p_actor_principal_id, v_scope_tenant_id,
                               'authz.scopes.write')
    then
        raise exception
            'principal % cannot attach scope % to role %: does not hold it at tenant % and does not own its definition',
            p_actor_principal_id, v_scope_name, p_role_id, v_tenant_id;
    end if;

    insert into authz.role_scopes (role_id, scope_id)
    values (p_role_id, p_scope_id)
    on conflict do nothing;
end;
$function$
;


