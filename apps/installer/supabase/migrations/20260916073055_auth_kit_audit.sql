drop function if exists "authz"."add_role_scope"(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid);

drop function if exists "authz"."create_api_key"(p_actor_principal_id uuid, p_tenant_id uuid, p_label text, p_expires_at timestamp with time zone);

drop function if exists "authz"."create_role"(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text, p_crosses_boundary boolean);

drop function if exists "authz"."create_scope"(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text);

drop function if exists "authz"."create_tenant"(p_actor_principal_id uuid, p_parent_id uuid, p_name text);

drop function if exists "authz"."create_workspace"(p_actor_principal_id uuid, p_name text);

drop function if exists "authz"."grant_role"(p_actor_principal_id uuid, p_principal_id uuid, p_role_id uuid, p_tenant_id uuid, p_expires_at timestamp with time zone);

drop function if exists "authz"."invite_user"(p_actor_principal_id uuid, p_tenant_id uuid, p_email text, p_role_id uuid);

drop function if exists "authz"."remove_role_scope"(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid);

drop function if exists "authz"."revoke_api_key"(p_actor_principal_id uuid, p_api_key_id uuid);

drop function if exists "authz"."revoke_binding"(p_actor_principal_id uuid, p_binding_id uuid);

drop function if exists "authz"."update_role"(p_actor_principal_id uuid, p_role_id uuid, p_name text, p_description text, p_crosses_boundary boolean);

drop function if exists "authz"."update_tenant"(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_inherit boolean);

alter table "authz"."audit_logs" drop column "updated_at";

alter table "authz"."audit_logs" add column "outcome" text not null default 'success'::text;

alter table "authz"."audit_logs" add column "reason" text;

alter table "authz"."audit_logs" alter column "method" drop not null;

alter table "authz"."audit_logs" alter column "request_id" drop not null;

alter table "authz"."audit_logs" alter column "route" drop not null;

alter table "authz"."audit_logs" add constraint "audit_logs_outcome_check" CHECK ((outcome = ANY (ARRAY['success'::text, 'denied'::text]))) not valid;

alter table "authz"."audit_logs" validate constraint "audit_logs_outcome_check";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.add_role_scope(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    -- Logged against the role, not the role_scopes pair: role_scopes has no id of its own,
    -- and the role is what an auditor tracks -- attaching a scope widens every binding to it.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'add_role_scope', 'role', p_role_id,
                            null,
                            jsonb_build_object('scope_id', p_scope_id,
                                               'scope_name', v_scope_name),
                            'success', null, p_request_ctx);
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_api_key(p_actor_principal_id uuid, p_tenant_id uuid, p_label text, p_expires_at timestamp with time zone DEFAULT NULL::timestamp with time zone, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    -- Neither the key nor its hash goes in the audit row, for the same reason list_api_keys
    -- does not return key_hash: a path that cannot carry it cannot leak it. The prefix is the
    -- public half and is what identifies the key in every other view.
    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'create_api_key', 'api_key', v_key_id,
                            null,
                            jsonb_build_object('label', p_label,
                                               'key_prefix', v_prefix,
                                               'expires_at', p_expires_at),
                            'success', null, p_request_ctx);

    return v_key;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_role(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text, p_crosses_boundary boolean DEFAULT false, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'create_role', 'role', v_role_id,
                            null,
                            jsonb_build_object('name', p_name,
                                               'description', p_description,
                                               'crosses_boundary',
                                               coalesce(p_crosses_boundary, false)),
                            'success', null, p_request_ctx);

    return v_role_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_scope(p_actor_principal_id uuid, p_tenant_id uuid, p_name text, p_description text DEFAULT NULL::text, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'create_scope', 'scope', v_scope_id,
                            null,
                            jsonb_build_object('name', p_name,
                                               'description', p_description),
                            'success', null, p_request_ctx);

    return v_scope_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_tenant(p_actor_principal_id uuid, p_parent_id uuid, p_name text, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    -- Logged at the new tenant rather than the parent: that is where the row lives, and where
    -- audit.read has to be held to read it. Authority at the parent reaches it either way.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'create_tenant', 'tenant', v_tenant_id,
                            null,
                            jsonb_build_object('parent_id', p_parent_id, 'name', p_name),
                            'success', null, p_request_ctx);

    return v_tenant_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.create_workspace(p_actor_principal_id uuid, p_name text, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    -- The one write with no scope check, so it is the one an auditor most wants to see. The
    -- self-grant is part of the row: this is the only place authority appears from nowhere.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'create_workspace', 'tenant', v_tenant_id,
                            null,
                            jsonb_build_object('parent_id', v_master_id,
                                               'name', p_name,
                                               'self_granted_role_id', v_tenant_admin_id),
                            'success', null, p_request_ctx);

    return v_tenant_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.grant_role(p_actor_principal_id uuid, p_principal_id uuid, p_role_id uuid, p_tenant_id uuid, p_expires_at timestamp with time zone DEFAULT NULL::timestamp with time zone, p_request_ctx jsonb DEFAULT NULL::jsonb)
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
    v_before       jsonb;
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
    --
    -- The second clause is the same ownership escape add_role_scope carries, and it is needed
    -- for the same reason: a freshly defined scope is held by nobody, so a pure holds-it check
    -- makes a role carrying one ungrantable by anyone -- including the actor who just defined
    -- it. That would leave a tenant able to define app scopes and roles it could never hand
    -- out. Owning the definition (authz.scopes.write at the scope's own tenant) counts as
    -- holding it for the purpose of delegating it onward.
    --
    -- It cannot be turned on the built-ins: the authz. namespace is reserved to the master by
    -- create_scope, and a tenant admin holds no authz.scopes.write there.
    select string_agg(s.name, ', ' order by s.name) into v_missing
      from authz.role_scopes rs
      join authz.scopes s on s.id = rs.scope_id
     where rs.role_id = p_role_id
       and not authz.has_scope(p_actor_principal_id, p_tenant_id, s.name)
       and not authz.has_scope(p_actor_principal_id, s.tenant_id,
                               'authz.scopes.write');

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

    -- Read before writing, for the audit row only. A grant that reinstates a revoked binding
    -- and a grant that creates one are the same call and the same return value, and which of
    -- the two happened is exactly what an auditor is reading the log to find out. One lookup
    -- on the unique key that the upsert below is about to use anyway.
    select jsonb_build_object('binding_id', rb.id,
                              'granted_at', rb.granted_at,
                              'expires_at', rb.expires_at,
                              'revoked_at', rb.revoked_at)
      into v_before
      from authz.role_bindings rb
     where rb.principal_id = p_principal_id
       and rb.role_id = p_role_id
       and rb.tenant_id = p_tenant_id;

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

    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'grant_role', 'role_binding', v_binding_id,
                            v_before,
                            jsonb_build_object('principal_id', p_principal_id,
                                               'role_id', p_role_id,
                                               'tenant_id', p_tenant_id,
                                               'expires_at', p_expires_at),
                            'success', null, p_request_ctx);

    return v_binding_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.invite_user(p_actor_principal_id uuid, p_tenant_id uuid, p_email text, p_role_id uuid, p_request_ctx jsonb DEFAULT NULL::jsonb)
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
    v_provisioned  boolean := false;
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
        v_provisioned := true;

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
    -- visibility, the holds-it rule, and reinstating a revoked binding. The request context
    -- travels with it, so the grant_role row it writes belongs to the same request as this
    -- one -- an invite leaves two rows, which is the truth: an identity decision and a grant.
    perform authz.grant_role(p_actor_principal_id, v_principal_id, p_role_id, p_tenant_id,
                             null, p_request_ctx);

    -- The address is recorded, which is the one place an audit row carries PII by design:
    -- the action *is* the address. It outlives the account deliberately -- deleting the
    -- Supabase user unlinks the identity and leaves the trail intact -- so an erasure request
    -- reaches this table and is not satisfied by deleting the auth.users row.
    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'invite_user', 'user', v_user_id,
                            null,
                            jsonb_build_object('email', p_email,
                                               'role_id', p_role_id,
                                               'tenant_id', p_tenant_id,
                                               'principal_id', v_principal_id,
                                               'provisioned', v_provisioned),
                            'success', null, p_request_ctx);

    return v_user_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.list_audit_logs(p_actor_principal_id uuid, p_tenant_id uuid DEFAULT NULL::uuid, p_actor_id uuid DEFAULT NULL::uuid, p_action text DEFAULT NULL::text, p_target_type text DEFAULT NULL::text, p_target_id uuid DEFAULT NULL::uuid, p_request_id text DEFAULT NULL::text, p_outcome text DEFAULT NULL::text, p_from timestamp with time zone DEFAULT NULL::timestamp with time zone, p_to timestamp with time zone DEFAULT NULL::timestamp with time zone, p_limit integer DEFAULT 100, p_after text DEFAULT NULL::text)
 RETURNS TABLE(audit_log_id uuid, actor_principal_id uuid, actor_kind text, request_id text, method text, route text, action text, target_type text, target_id uuid, tenant_id uuid, outcome text, reason text, before jsonb, after jsonb, ip text, user_agent text, created_at timestamp with time zone, page_cursor text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
with readable as materialized (
    select t.id
      from authz.tenants t
     where (p_tenant_id is null or t.id = p_tenant_id)
       and authz.has_scope(p_actor_principal_id, t.id, 'authz.audit.read')
),
platform as materialized (
    -- The coalesce in the audit_logs policy, spelled out: a row with no tenant requires
    -- audit.read at the master. Excluded outright when a tenant filter is given, since such
    -- a row belongs to no tenant.
    select p_tenant_id is null
       and authz.has_scope(p_actor_principal_id, authz.master_tenant_id(),
                           'authz.audit.read') as visible
)
select a.id, a.actor_principal_id, a.actor_kind, a.request_id, a.method, a.route,
       a.action, a.target_type, a.target_id, a.tenant_id, a.outcome, a.reason,
       a.before, a.after, a.ip, a.user_agent, a.created_at,
       a.id::text || a.created_at::text
  from authz.audit_logs a
 where case
           when a.tenant_id is null then (select p.visible from platform p)
           else a.tenant_id in (select r.id from readable r)
       end
   and (p_actor_id is null or a.actor_principal_id = p_actor_id)
   and (p_action is null or a.action = p_action)
   and (p_target_type is null or a.target_type = p_target_type)
   and (p_target_id is null or a.target_id = p_target_id)
   and (p_request_id is null or a.request_id = p_request_id)
   and (p_outcome is null or a.outcome = p_outcome)
   and (p_from is null or a.created_at >= p_from)
   and (p_to is null or a.created_at < p_to)
   -- Descending keyset, so the cursor comparison is < rather than >. The cursor is still the
   -- row's id followed by its sort key: an id is always 36 characters, which is what lets the
   -- two halves be split without a delimiter.
   and (p_after is null
        or (a.created_at, a.id)
           < (substr(p_after, 37)::timestamptz, substr(p_after, 1, 36)::uuid))
 order by a.created_at desc, a.id desc
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$function$
;

CREATE OR REPLACE FUNCTION authz.log_audit(p_actor_principal_id uuid, p_tenant_id uuid, p_action text, p_target_type text, p_target_id uuid DEFAULT NULL::uuid, p_before jsonb DEFAULT NULL::jsonb, p_after jsonb DEFAULT NULL::jsonb, p_outcome text DEFAULT 'success'::text, p_reason text DEFAULT NULL::text, p_request_ctx jsonb DEFAULT NULL::jsonb)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_id     uuid := gen_random_uuid();
    v_actor  uuid;
    v_tenant uuid;
    v_kind   authz.principal_kind;
begin
    -- Nothing in this function may raise. It runs inside the transaction of the write it
    -- describes, so anything that fails here fails the write itself -- a grant lost to a
    -- malformed audit row would be the logging making the system less correct, not more.
    -- Hence both foreign keys are resolved rather than trusted, and the two NOT NULL text
    -- columns and the outcome check are satisfied by construction below.
    --
    -- Resolving rather than trusting matters most for denials, which are logged for exactly
    -- the input that caused them -- often a tenant id the caller invented. A foreign key
    -- violation there would turn a clean 403 into a 500. The unresolvable value is not lost:
    -- a denial records what was asked about as the target, which carries no foreign key.
    select p.id, p.kind into v_actor, v_kind
      from authz.principals p
     where p.id = p_actor_principal_id;

    select t.id into v_tenant
      from authz.tenants t
     where t.id = p_tenant_id;

    insert into authz.audit_logs (id, actor_principal_id, actor_kind,
                                  request_id, method, route,
                                  action, target_type, target_id, tenant_id,
                                  outcome, reason, before, after, ip, user_agent)
    values (v_id, v_actor, v_kind::text,
            p_request_ctx ->> 'request_id',
            p_request_ctx ->> 'method',
            p_request_ctx ->> 'route',
            coalesce(p_action, 'unknown'),
            coalesce(p_target_type, 'unknown'),
            p_target_id, v_tenant,
            case when p_outcome = 'denied' then 'denied' else 'success' end,
            p_reason, p_before, p_after,
            p_request_ctx ->> 'ip',
            p_request_ctx ->> 'user_agent');

    return v_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.prune_audit_logs(p_before timestamp with time zone, p_tenant_id uuid DEFAULT NULL::uuid, p_limit integer DEFAULT 1000)
 RETURNS TABLE(deleted_count integer, lock_acquired boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_deleted integer;
begin
    -- No default cutoff, ever. This is the one function here that destroys history, and an
    -- argument the caller forgot must not mean "everything".
    if p_before is null then
        raise exception 'prune_audit_logs requires an explicit cutoff';
    end if;

    if not pg_try_advisory_xact_lock(
               hashtext('authz.prune_audit_logs:' || coalesce(p_tenant_id::text, '*'))) then
        return query select 0::integer, false;

        return;
    end if;

    with doomed as (
        select a.id
          from authz.audit_logs a
         where a.created_at < p_before
           and (p_tenant_id is null or a.tenant_id = p_tenant_id)
           -- Prune records are never pruned. They are the record of what was destroyed, which
           -- is the one thing that has to outlive the destruction -- otherwise a trail with a
           -- hole in it is indistinguishable from a trail that never had those rows. One row
           -- per prune that actually deleted something, so this exemption stays small.
           and a.action <> 'prune_audit_logs'
         order by a.created_at
         limit greatest(coalesce(p_limit, 1000), 1)
           for update skip locked
    )
    delete from authz.audit_logs a
     using doomed d
     where a.id = d.id;

    get diagnostics v_deleted = row_count;

    -- Logged only when something was actually deleted. A retention job that runs every five
    -- minutes on three replicas and finds nothing would otherwise write more rows than it
    -- removes. The row is written after the delete, so its own created_at is later than any
    -- cutoff this call could have used and it cannot delete its own record.
    if v_deleted > 0 then
        perform authz.log_audit(null, p_tenant_id,
                                'prune_audit_logs', 'audit_log', null,
                                null,
                                jsonb_build_object('before', p_before,
                                                   'tenant_id', p_tenant_id,
                                                   'deleted_count', v_deleted),
                                'success', null, null);
    end if;

    return query select v_deleted, true;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.remove_role_scope(p_actor_principal_id uuid, p_role_id uuid, p_scope_id uuid, p_request_ctx jsonb DEFAULT NULL::jsonb)
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

    -- The hard delete is exactly why `before` matters here: after this commits, the audit row
    -- is the only record that the pair ever existed.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'remove_role_scope', 'role', p_role_id,
                            jsonb_build_object('scope_id', p_scope_id),
                            null,
                            'success', null, p_request_ctx);
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.revoke_api_key(p_actor_principal_id uuid, p_api_key_id uuid, p_request_ctx jsonb DEFAULT NULL::jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id  uuid;
    v_revoked_at timestamptz;
    v_found      boolean;
    v_before     jsonb;
begin
    select true, k.tenant_id, k.revoked_at,
           jsonb_build_object('label', k.label, 'key_prefix', k.key_prefix,
                              'revoked_at', k.revoked_at)
      into v_found, v_tenant_id, v_revoked_at, v_before
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

    -- Revoking a key withdraws everything its principal held, without touching a binding, so
    -- this row is the only trace of an authority change that leaves role_bindings untouched.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'revoke_api_key', 'api_key', p_api_key_id,
                            v_before,
                            (select jsonb_build_object('revoked_at', k.revoked_at)
                               from authz.api_keys k
                              where k.id = p_api_key_id),
                            'success', null, p_request_ctx);
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.revoke_binding(p_actor_principal_id uuid, p_binding_id uuid, p_request_ctx jsonb DEFAULT NULL::jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id  uuid;
    v_revoked_at timestamptz;
    v_found      boolean;
    v_before     jsonb;
begin
    select true, rb.tenant_id, rb.revoked_at,
           jsonb_build_object('principal_id', rb.principal_id,
                              'role_id', rb.role_id,
                              'tenant_id', rb.tenant_id,
                              'revoked_at', rb.revoked_at)
      into v_found, v_tenant_id, v_revoked_at, v_before
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

    -- Logged even when the call was a no-op on an already-revoked binding. The attempt is
    -- itself the interesting fact during an incident, and `before` says which it was: a row
    -- whose before.revoked_at is already set changed nothing.
    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'revoke_binding', 'role_binding', p_binding_id,
                            v_before,
                            (select jsonb_build_object('revoked_at', rb.revoked_at)
                               from authz.role_bindings rb
                              where rb.id = p_binding_id),
                            'success', null, p_request_ctx);
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.update_role(p_actor_principal_id uuid, p_role_id uuid, p_name text DEFAULT NULL::text, p_description text DEFAULT NULL::text, p_crosses_boundary boolean DEFAULT NULL::boolean, p_request_ctx jsonb DEFAULT NULL::jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_tenant_id uuid;
    v_current   boolean;
    v_before    jsonb;
begin
    select r.tenant_id, r.crosses_boundary,
           jsonb_build_object('name', r.name, 'description', r.description,
                              'crosses_boundary', r.crosses_boundary)
      into v_tenant_id, v_current, v_before
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

    perform authz.log_audit(p_actor_principal_id, v_tenant_id,
                            'update_role', 'role', p_role_id,
                            v_before,
                            (select jsonb_build_object('name', r.name,
                                                       'description', r.description,
                                                       'crosses_boundary', r.crosses_boundary)
                               from authz.roles r
                              where r.id = p_role_id),
                            'success', null, p_request_ctx);
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.update_tenant(p_actor_principal_id uuid, p_tenant_id uuid, p_name text DEFAULT NULL::text, p_inherit boolean DEFAULT NULL::boolean, p_request_ctx jsonb DEFAULT NULL::jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_parent_id uuid;
    v_current   boolean;
    v_found     boolean;
    v_before    jsonb;
begin
    select true, t.parent_id, t.inherit,
           jsonb_build_object('name', t.name, 'inherit', t.inherit)
      into v_found, v_parent_id, v_current, v_before
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

    -- A change to inherit is a change to who can see this tenant at all, so the before/after
    -- pair is the record of when a subtree was cut off from its parent and by whom.
    perform authz.log_audit(p_actor_principal_id, p_tenant_id,
                            'update_tenant', 'tenant', p_tenant_id,
                            v_before,
                            (select jsonb_build_object('name', t.name, 'inherit', t.inherit)
                               from authz.tenants t
                              where t.id = p_tenant_id),
                            'success', null, p_request_ctx);
end;
$function$
;


