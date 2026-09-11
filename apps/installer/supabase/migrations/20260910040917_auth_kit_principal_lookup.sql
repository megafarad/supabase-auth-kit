set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authz.principal_for_auth_user(p_auth_user_id uuid)
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select p.id
  from authz.users u
  join authz.principals p on p.user_id = u.id
 where u.auth_user_id = p_auth_user_id
   and u.disabled_at is null
   and u.deleted_at is null;
$function$
;

CREATE OR REPLACE FUNCTION authz.current_principal_id()
 RETURNS uuid
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
select authz.principal_for_auth_user((select auth.uid()));
$function$
;



-- principal_for_auth_user is new, so it arrived with the built-in PUBLIC EXECUTE grant. Taking
-- it off again is a standing obligation of every migration that adds a function here: no
-- ALTER DEFAULT PRIVILEGES form can withhold that grant, verified three ways in
-- 20260909060000_auth_kit_privileges.sql. Idempotent for the functions already revoked.
--
-- service_role needs no explicit grant: the default privileges set in that same migration
-- carry its EXECUTE onto functions created here later.
revoke execute on all functions in schema "authz" from public;
