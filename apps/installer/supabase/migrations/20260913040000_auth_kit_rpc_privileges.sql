-- Makes authz callable through PostgREST by service_role, and by nobody else.
--
-- Hand-written, for the same reason as 20260909060000_auth_kit_privileges.sql: migra does not
-- diff privileges at all, so a declarative file in schemas/ would never reach a migration.
--
-- service_role is the role PostgREST switches into for a secret key (sb_secret_...) or the
-- legacy service_role JWT. Granting it USAGE lets a server-side supabase-js client call these
-- functions with .schema('authz').rpc(...) once the project exposes the schema -- which is a
-- project setting ([api] schemas locally, the dashboard's API settings when hosted), not
-- something a migration can do. Until it is exposed, none of this is reachable over HTTP, and
-- a direct Postgres connection as the owner is unaffected either way.
--
-- The access posture this encodes is server-only: anon and authenticated are given nothing,
-- and the functions that take an explicit actor are safe to reach only because whoever holds
-- a secret key is already trusted to name one. Do not grant anything here to anon or
-- authenticated. That is a different posture, with its own prerequisites -- see the model doc.

-- 1. New functions no longer inherit service_role EXECUTE.
--
-- 20260909060000 set a default so a function added later would be callable without anyone
-- remembering to grant it. That was harmless while the schema was unreachable. Now that
-- service_role can reach it over HTTP, the same default would expose every future function --
-- including anything as dangerous as provision_admin -- the moment it is created. Exposure is
-- therefore opt-in, one function at a time, below.
alter default privileges in schema "authz"
    revoke execute on functions from "service_role";

-- 2. Start from nothing.
revoke execute on all functions in schema "authz" from public;
revoke execute on all functions in schema "authz" from "service_role";
revoke all on schema "authz" from "anon", "authenticated";
revoke execute on all functions in schema "authz" from "anon", "authenticated";

-- 3. Reach the schema. USAGE is required to resolve anything in it by name, and PostgREST
-- refuses a role without it before looking at function privileges.
grant usage on schema "authz" to "service_role";

-- 4. Exactly the functions packages/core calls, and no others. Every one of them either takes
-- the actor explicitly and checks its authority, or answers an identity question the server
-- needs before it has an actor.
--
-- Deliberately absent:
--   provision_admin, reclaim_identity  no authorization check at all, by design. Operator
--                                      bootstrap tools for the SQL editor, which runs as the
--                                      owner and does not need this grant.
--   claim_auth_user                    the auth.users trigger. supabase_auth_admin keeps its
--                                      own grant from 20260909060000.
--   bindings_in_force                  invoker and inlinable on purpose; as an invoker it
--                                      must never be callable by anyone but the owner.
--   tenant_chain, effective_roles, effective_scope_defs, effective_bindings, email_id,
--   master_tenant_id, current_principal_id, can_read_user, can_read_principal,
--   role_tenant_id                     internals and policy predicates. The functions that
--                                      use them run as the owner and need no grant.
--
-- An integration test asserts service_role's EXECUTE set equals this list, so adding a
-- function to core without adding it here fails loudly rather than at a customer's runtime.
grant execute on function
    -- identity
    "authz"."principal_for_auth_user"(uuid),
    "authz"."verify_api_key"(text),
    "authz"."principal_is_active"(uuid),
    -- authorization
    "authz"."has_scope"(uuid, uuid, text),
    "authz"."effective_scopes"(uuid, uuid),
    -- writes
    "authz"."grant_role"(uuid, uuid, uuid, uuid, timestamptz),
    "authz"."invite_user"(uuid, uuid, text, uuid),
    "authz"."revoke_binding"(uuid, uuid),
    "authz"."create_role"(uuid, uuid, text, text, boolean),
    "authz"."update_role"(uuid, uuid, text, text, boolean),
    "authz"."add_role_scope"(uuid, uuid, uuid),
    "authz"."remove_role_scope"(uuid, uuid, uuid),
    "authz"."create_scope"(uuid, uuid, text, text),
    "authz"."create_tenant"(uuid, uuid, text),
    "authz"."create_workspace"(uuid, text),
    "authz"."update_tenant"(uuid, uuid, text, boolean),
    "authz"."create_api_key"(uuid, uuid, text, timestamptz),
    "authz"."revoke_api_key"(uuid, uuid),
    -- reads
    "authz"."get_tenant"(uuid, uuid),
    "authz"."list_child_tenants"(uuid, uuid, integer, text),
    "authz"."list_principal_bindings"(uuid, uuid, integer, text),
    "authz"."list_tenant_bindings"(uuid, uuid, boolean, integer, text),
    "authz"."list_roles"(uuid, uuid, integer, text),
    "authz"."list_role_scopes"(uuid, uuid, uuid, integer, text),
    "authz"."list_scopes"(uuid, uuid, integer, text),
    "authz"."list_api_keys"(uuid, uuid, integer, text)
to "service_role";

-- PostgREST caches the schema. Supabase reloads it on DDL, but a grant is not DDL, so ask.
notify pgrst, 'reload schema';
