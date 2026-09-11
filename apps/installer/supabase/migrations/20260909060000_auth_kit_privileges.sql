-- Takes the default PUBLIC EXECUTE grant off every authz function.
--
-- Hand-written, and the second exception to "migrations are generated, never hand-written".
-- The reason differs from the bootstrap's: migra does not diff privileges at all. Tested
-- directly -- with these statements declared in schemas/ and absent from the database,
-- `supabase db diff` reported "No schema changes found" while all 30 functions still had
-- PUBLIC EXECUTE. A declarative file would never reach a migration, so this cannot live in
-- schemas/. The same blindness makes it stable here: later diffs will not undo it.
--
-- Why it matters. Postgres grants EXECUTE on every new function to PUBLIC. Nothing has USAGE
-- on this schema under posture A, so that is unreachable today -- but it means the day anyone
-- grants USAGE, every function becomes callable, including two that carry no authorization
-- check whatsoever by design: provision_admin(email) hands out master admin, and
-- reclaim_identity(email) relinks a retired identity to whoever now holds the address. Both
-- are operator bootstrap tools meant for a SQL editor, not an API.

revoke execute on all functions in schema "authz" from public;

-- Restores what the revoke above takes away from service_role. PUBLIC was its only grant, so
-- revoking PUBLIC alone left it unable to call anything -- which would break an adapter that
-- reaches the schema as service_role rather than as the owner. postgres owns these functions
-- and holds EXECUTE implicitly, so an owner connection is unaffected either way.
grant execute on all functions in schema "authz" to "service_role";

-- Carries the service_role grant onto functions added later, so a new function is usable
-- without remembering to grant it. Written without FOR ROLE so it applies to whoever runs the
-- migration, which is the role that will own what it creates.
--
-- It does NOT withhold PUBLIC on those future functions, and no ALTER DEFAULT PRIVILEGES form
-- does. Verified three ways: a bare `REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` stores no
-- pg_default_acl row at all; pairing it with a grant does store one, `{service_role=X/postgres}`
-- with no PUBLIC entry; and even then a newly created function still comes out with PUBLIC
-- EXECUTE. The built-in default is applied regardless of the stored ACL.
--
-- ==> CONSEQUENCE: any later migration that ADDS a function to authz must repeat the bulk
--     revoke above. There is no way to make it automatic. An invariant test asserting that no
--     authz function has PUBLIC EXECUTE is the way to catch a forgotten one.
alter default privileges in schema "authz"
    grant execute on functions to "service_role";

-- The claim trigger fires on auth.users, which GoTrue writes as supabase_auth_admin. Granted
-- explicitly so that revoking PUBLIC cannot break signup.
grant execute on function "authz"."claim_auth_user"() to "supabase_auth_admin";
