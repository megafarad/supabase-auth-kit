alter table "authz"."users" add column "claimed_at" timestamp with time zone;

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.reclaim_identity(p_email text)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
    v_user_id      uuid;
    v_auth_user_id uuid;
begin
    -- STRICT on both: no identity, or no confirmed account, should fail loudly rather than
    -- silently doing nothing.
    select u.id into strict v_user_id
      from authz.users u
     where u.email_id = authz.email_id(p_email);

    if exists (
        select 1 from authz.users u
         where u.id = v_user_id and u.auth_user_id is not null
    ) then
        raise exception
            'authz.users row for % is already linked; unlink it before reclaiming', p_email;
    end if;

    select a.id into strict v_auth_user_id
      from auth.users a
     where authz.email_id(a.email) = authz.email_id(p_email)
       and a.email_confirmed_at is not null;

    update authz.users u
       set auth_user_id = v_auth_user_id,
           email        = p_email,
           claimed_at   = now(),
           updated_at   = now()
     where u.id = v_user_id;

    insert into authz.principals (id, kind, user_id)
    values (gen_random_uuid(), 'user', v_user_id)
    on conflict do nothing;

    return v_user_id;
end;
$function$
;

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

    -- claimed_at is null means never linked, so this row is a genuine provision waiting to
    -- be taken. A row whose claimed_at is set but whose auth_user_id has gone back to null
    -- is a retired identity -- its Supabase account was deleted -- and is deliberately not
    -- auto-claimed, so re-registering a departed admin's address inherits nothing.
    update authz.users u
       set auth_user_id = new.id,
           email        = new.email,
           claimed_at   = now(),
           updated_at   = now()
     where u.email_id = authz.email_id(new.email)
       and u.auth_user_id is null
       and u.claimed_at is null
    returning u.id into v_user_id;

    if v_user_id is null then
        -- Either an ordinary signup with nothing waiting, which gets a fresh identity
        -- holding no roles, or an address already spoken for by a retired identity, where
        -- users_email_id_uq makes this a no-op and the account ends up with no authz
        -- identity at all. The second case is fail-closed on purpose: it grants nothing,
        -- and an administrator uses authz.reclaim_identity() to decide otherwise.
        v_user_id := gen_random_uuid();

        insert into authz.users (id, auth_user_id, email_id, email, claimed_at)
        values (v_user_id, new.id, authz.email_id(new.email), new.email, now())
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


