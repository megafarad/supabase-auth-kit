drop index if exists "authz"."users_auth_user_id_idx";

alter table "authz"."users" alter column "auth_user_id" drop not null;

CREATE UNIQUE INDEX users_auth_user_id_uq ON authz.users USING btree (auth_user_id);

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.claim_auth_user()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_user_id uuid;
begin
    if new.email is null or new.email_confirmed_at is null then
        return new;
    end if;

    -- Already linked. Keeps repeated UPDATEs on auth.users cheap and prevents the insert
    -- below from minting a second identity for the same account.
    if exists (select 1 from authz.users u where u.auth_user_id = new.id) then
        return new;
    end if;

    update authz.users u
       set auth_user_id = new.id,
           email        = new.email,
           updated_at   = now()
     where u.email_id = authz.email_id(new.email)
       and u.auth_user_id is null
    returning u.id into v_user_id;

    if v_user_id is null then
        -- Ordinary signup with no outstanding provision: an identity with no roles.
        v_user_id := gen_random_uuid();

        insert into authz.users (id, auth_user_id, email_id, email)
        values (v_user_id, new.id, authz.email_id(new.email), new.email)
        on conflict do nothing
        returning id into v_user_id;
    end if;

    -- Every authz user needs a principal before it can hold a binding. Idempotent via
    -- principals_user_id_uq, so a provisioned user that already has one is untouched.
    if v_user_id is not null then
        insert into authz.principals (id, kind, user_id)
        values (gen_random_uuid(), 'user', v_user_id)
        on conflict do nothing;
    end if;

    return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION authz.email_id(p_email text)
 RETURNS character
 LANGUAGE sql
 IMMUTABLE STRICT
 SET search_path TO ''
AS $function$
select encode(sha256(lower(btrim(p_email))::bytea), 'hex')::char(64);
$function$
;

CREATE OR REPLACE FUNCTION authz.provision_admin(p_email text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_master_id    uuid;
    v_admin_role   uuid;
    v_user_id      uuid;
    v_principal_id uuid;
begin
    -- STRICT: fail loudly rather than provisioning into a database whose bootstrap
    -- migration has not run.
    select t.id into strict v_master_id
      from authz.tenants t
     where t.parent_id is null;

    select r.id into strict v_admin_role
      from authz.roles r
     where r.tenant_id = v_master_id
       and r.name = 'admin';

    -- Reuse whatever identity already exists for this address, claimed or not.
    select u.id into v_user_id
      from authz.users u
     where u.email_id = authz.email_id(p_email);

    if v_user_id is null then
        v_user_id := gen_random_uuid();

        insert into authz.users (id, auth_user_id, email_id, email)
        values (v_user_id, null, authz.email_id(p_email), p_email);
    end if;

    select p.id into v_principal_id
      from authz.principals p
     where p.user_id = v_user_id;

    if v_principal_id is null then
        v_principal_id := gen_random_uuid();

        insert into authz.principals (id, kind, user_id)
        values (v_principal_id, 'user', v_user_id);
    end if;

    -- Self-granted. This binding is the root of trust, so there is no earlier principal to
    -- name as its granter; recording the grantee is more honest than inventing a system
    -- principal, which principals_exactly_one_of would not permit anyway.
    insert into authz.role_bindings (
        id, principal_id, role_id, tenant_id, granted_by_principal_id
    )
    values (
        gen_random_uuid(), v_principal_id, v_admin_role, v_master_id, v_principal_id
    )
    on conflict do nothing;

    return v_user_id;
end;
$function$
;


