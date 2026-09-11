set check_function_bodies = off;

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

    -- Coarsened deliberately. An unconditional write takes a row lock on the key for every
    -- request that presents it, which serialises all concurrent traffic for a single key --
    -- the busier the key, the worse it gets, and an adapter cannot fix that by calling this
    -- once per request. Skipping the write while the timestamp is already fresh removes the
    -- contention, and costs only sub-minute resolution on a field nothing reads that finely.
    update authz.api_keys k
       set last_used_at = now(),
           updated_at   = now()
     where k.id = v_key_id
       and (k.last_used_at is null
            or k.last_used_at < now() - interval '1 minute');

    select p.id into v_principal_id
      from authz.principals p
     where p.api_key_id = v_key_id;

    return v_principal_id;
end;
$function$
;



-- No new function, but verify_api_key was replaced; keeps the PUBLIC EXECUTE invariant true
-- regardless of whether CREATE OR REPLACE resets an ACL. Idempotent.
revoke execute on all functions in schema "authz" from public;
