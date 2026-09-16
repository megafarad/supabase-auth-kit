-- Restores and extends service_role's EXECUTE set after the audit migration.
--
-- Hand-written, for the same reason as the two privileges migrations before it: migra does not
-- diff privileges at all, so a declarative file in schemas/ would never reach a migration.
--
-- This one exists because **20260916070335 dropped thirteen functions and recreated them**.
-- Adding p_request_ctx changes a signature, and a signature change cannot be a create-or-replace
-- when overloading is forbidden -- PostgREST passes arguments by name and cannot tell overloads
-- apart. A dropped function takes every GRANT made against it, so all thirteen lost the EXECUTE
-- that 20260913040000 gave them and are unreachable over PostgREST until re-granted here.
--
-- Deployment note: between the two migrations, a supabase-js transport gets 42501 on every
-- write. They are applied in one `supabase db push`, so the window is the length of that push,
-- but a deployment that applies migrations in stages should apply both together.

-- 1. Start from nothing, again. No ALTER DEFAULT PRIVILEGES form prevents a new function from
-- getting the built-in PUBLIC EXECUTE, so every migration that creates one repeats this --
-- log_audit and list_audit_logs are new, and the thirteen recreated ones are new rows in
-- pg_proc as far as privileges are concerned.
revoke execute on all functions in schema "authz" from public;
revoke execute on all functions in schema "authz" from "anon", "authenticated";

-- 2. The thirteen, with their new signatures. Same list as 20260913040000, one jsonb wider.
grant execute on function
    "authz"."grant_role"(uuid, uuid, uuid, uuid, timestamptz, jsonb),
    "authz"."invite_user"(uuid, uuid, text, uuid, jsonb),
    "authz"."revoke_binding"(uuid, uuid, jsonb),
    "authz"."create_role"(uuid, uuid, text, text, boolean, jsonb),
    "authz"."update_role"(uuid, uuid, text, text, boolean, jsonb),
    "authz"."add_role_scope"(uuid, uuid, uuid, jsonb),
    "authz"."remove_role_scope"(uuid, uuid, uuid, jsonb),
    "authz"."create_scope"(uuid, uuid, text, text, jsonb),
    "authz"."create_tenant"(uuid, uuid, text, jsonb),
    "authz"."create_workspace"(uuid, text, jsonb),
    "authz"."update_tenant"(uuid, uuid, text, boolean, jsonb),
    "authz"."create_api_key"(uuid, uuid, text, timestamptz, jsonb),
    "authz"."revoke_api_key"(uuid, uuid, jsonb)
to "service_role";

-- 3. The audit pair.
--
-- log_audit is granted because a refusal cannot log itself: every guard raises, which rolls
-- back the transaction and any audit row written inside it, so the caller writes the denied row
-- afterwards. That is packages/core's write API and enforceGuard, over whichever transport the
-- consumer chose -- so it has to be reachable over PostgREST like any other call core makes.
--
-- It takes an explicit actor, like the writes, and is safe on the same terms: whoever holds a
-- secret key is already trusted to name any actor. It is emphatically NOT safe to grant to
-- anon or authenticated, which could then forge rows against any principal. There is still no
-- authz.audit.write scope, and this grant is not one -- see the model doc's Audit log section.
grant execute on function
    "authz"."log_audit"(uuid, uuid, text, text, uuid, jsonb, jsonb, text, text, jsonb),
    "authz"."list_audit_logs"(uuid, uuid, uuid, text, text, uuid, text, text, timestamptz,
                              timestamptz, integer, text)
to "service_role";

-- 4. Pruning.
--
-- The one function here that takes no actor and checks no scope, which is why it gets its own
-- paragraph rather than joining the list above. Retention is a maintenance job: a cron worker
-- has no principal to name, the model has no system principal to invent, and naming a real one
-- would put a lie in the audit row. Authority is the connection, as it is for provision_admin
-- and reclaim_identity.
--
-- Unlike those two it is granted, because a supabase-js deployment reaches authz no other way
-- and would otherwise have no retention at all. The trust boundary is unchanged: a secret key
-- can already call grant_role naming any actor, so it already holds total authority here.
--
-- Under no circumstances grant this to anon or authenticated. There it would let any caller
-- erase their own trail, and `privileges.integration.test.ts` fails if either role can reach
-- anything in this schema at all.
grant execute on function
    "authz"."prune_audit_logs"(timestamptz, uuid, integer)
to "service_role";

-- PostgREST caches the schema. Supabase reloads it on DDL, but a grant is not DDL, so ask.
notify pgrst, 'reload schema';
