-- Functions for @sirhc77/supabase-auth-kit.
--
-- Declared, not hand-written: `supabase db diff` generates all of this, including the
-- trigger on auth.users at the bottom. That trigger has to be declared here rather than
-- created only in a migration -- db diff builds its shadow database from the same Supabase
-- base image, so auth objects are compared like any other, and a trigger that exists only
-- in migration history shows up in every subsequent diff as a drop.

-- Canonical hash behind authz.users.email_id. char(64) is SHA-256 hex; PG11+ has sha256()
-- in pg_catalog, so there is no pgcrypto dependency. Lowercased and trimmed -- provisioning
-- and claiming must agree on this exactly, or invites silently never match.
create or replace function authz.email_id(p_email text)
    returns char(64)
    language sql
    immutable
    strict
    set search_path = ''
as $$
select encode(sha256(lower(btrim(p_email))::bytea), 'hex')::char(64);
$$;

comment on function authz.email_id(text) is
    'Canonical SHA-256 hex of a normalised email address, as stored in authz.users.email_id.';


-- Links an auth.users row to its authz.users identity, claiming a row that was provisioned
-- by email beforehand or creating a fresh one for an ordinary signup.
--
-- Fires only once the address is confirmed. Claiming on INSERT would let anyone who knows
-- an invited address sign up under it and take the grants waiting there -- with
-- [auth.email] enable_confirmations = false the row is confirmed at signup and this is
-- equivalent, but the check keeps the trigger safe for projects that turn confirmation on.
create or replace function authz.claim_auth_user()
    returns trigger
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.claim_auth_user() is
    'AFTER INSERT OR UPDATE trigger on auth.users: links or creates the matching authz.users identity once the address is confirmed.';


-- The kit's only object outside its own schema. Narrowed to the two columns that can
-- trigger a claim so ordinary auth.users churn does not fire it.
create trigger on_auth_user_confirmed
    after insert or update of email, email_confirmed_at on auth.users
    for each row
execute function authz.claim_auth_user();


-- Deliberately re-links a retired identity to the account now holding its address, which
-- authz.claim_auth_user() will not do on its own. Use this when a Supabase account was
-- deleted and recreated for the same person; do NOT use it to hand a departed
-- administrator's identity, and its grants, to somebody else.
create or replace function authz.reclaim_identity(p_email text)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.reclaim_identity(text) is
    'Re-links a retired authz.users identity to the confirmed auth.users account now holding its address. Grants survive the relink -- verify the account belongs to the same person.';


-- Provisions an administrator by email address, before or after that person has an account.
-- Returns the authz.users id.
--
-- This is the bootstrap entry point: run it once after installing, from the Supabase SQL
-- editor or any psql session, e.g. select authz.provision_admin('me@example.com');
create or replace function authz.provision_admin(p_email text)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.provision_admin(text) is
    'Grants the master admin role to an email address, provisioning an unclaimed identity if that person has not signed up yet.';


-- ---------------------------------------------------------------------------------------
-- Resolution
--
-- Defined once here so the RLS policies and both framework adapters share one traversal
-- rather than reimplementing it. Everything below is SECURITY DEFINER because the authz
-- tables have RLS enabled with no policies; the owner bypasses RLS, so these functions are
-- the only sanctioned read path. The authz schema is not in [api] schemas, so none of this
-- is reachable through PostgREST.
-- ---------------------------------------------------------------------------------------

-- The master tenant, or null if the bootstrap has not run. Null propagates into has_scope()
-- as a tenant that matches nothing, so callers guarding on master authority fail closed.
create or replace function authz.master_tenant_id()
    returns uuid
    language sql
    stable
    security definer
    set search_path = ''
as $$
select t.id from authz.tenants t where t.parent_id is null;
$$;

comment on function authz.master_tenant_id() is
    'The single tenant with parent_id is null, or null if the bootstrap has not run.';


-- The ancestor walk, and the whole of the inherit/crosses_boundary rule.
--
-- Returns one row per tenant from p_tenant_id up to the master, each carrying a `crossed`
-- flag meaning "this tenant's own rows reach the starting tenant only if they cross a
-- boundary". The flag latches on when the walk steps *out of* a tenant marked
-- inherit = false: stepping from t to its parent sets crossed := crossed OR NOT t.inherit,
-- so t's own rows stay unfiltered while everything above t is filtered. Since crossing()
-- is a filter it distributes over the union, which is what lets a compositional definition
-- collapse into one upward pass.
--
-- For Master -> A -> B -> C with B.inherit = false this yields
--   C crossed=false, B crossed=false, A crossed=true, Master crossed=true.
create or replace function authz.tenant_chain(p_tenant_id uuid)
    returns table (tenant_id uuid, crossed boolean, depth integer)
    language sql
    stable
    security definer
    set search_path = ''
as $$
with recursive chain as (
    select t.id, t.parent_id, t.inherit, false as crossed_flag, 0 as lvl
      from authz.tenants t
     where t.id = p_tenant_id
    union all
    -- The depth cap is a guard, not a limit: tenants is a tree, but parent_id is only a
    -- self-FK and nothing forbids a cycle, which would otherwise spin forever.
    select p.id, p.parent_id, p.inherit, c.crossed_flag or not c.inherit, c.lvl + 1
      from chain c
      join authz.tenants p on p.id = c.parent_id
     where c.lvl < 64
)
select c.id, c.crossed_flag, c.lvl from chain c;
$$;

comment on function authz.tenant_chain(uuid) is
    'Ancestor chain of a tenant, each row flagged with whether an inherit = false cut lies between it and the starting tenant.';


-- Role definitions in scope at a tenant: nearest name wins.
create or replace function authz.effective_roles(p_tenant_id uuid)
    returns table (role_id uuid, name text, crosses_boundary boolean,
                   source_tenant_id uuid, depth integer)
    language sql
    stable
    security definer
    set search_path = ''
as $$
-- distinct on (name) ordered by depth is the left-biased merge: the closest definition of
-- each name survives and shadows the inherited one.
select distinct on (r.name)
       r.id, r.name, r.crosses_boundary, r.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.roles r on r.tenant_id = c.tenant_id
 where not c.crossed or r.crosses_boundary
 order by r.name, c.depth;
$$;

comment on function authz.effective_roles(uuid) is
    'Role definitions visible at a tenant, with nearer definitions shadowing inherited ones of the same name.';


-- Scope definitions in scope at a tenant: nearest name wins.
create or replace function authz.effective_scope_defs(p_tenant_id uuid)
    returns table (scope_id uuid, name text, source_tenant_id uuid, depth integer)
    language sql
    stable
    security definer
    set search_path = ''
as $$
-- scopes has no crosses_boundary of its own, so past a cut a scope is visible only by
-- hanging off a crossing role through role_scopes.
select distinct on (s.name)
       s.id, s.name, s.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.scopes s on s.tenant_id = c.tenant_id
 where not c.crossed
    or exists (
        select 1
          from authz.role_scopes rs
          join authz.roles r on r.id = rs.role_id
         where rs.scope_id = s.id
           and r.crosses_boundary
       )
 order by s.name, c.depth;
$$;

comment on function authz.effective_scope_defs(uuid) is
    'Scope definitions visible at a tenant. A scope crosses a boundary only by being attached to a crossing role.';


-- Every binding in force at a tenant, for any principal. The one place grants are read:
-- effective_bindings narrows it to a principal, and list_tenant_bindings lists it.
--
-- Deliberately NOT security definer and with no SET clause, which is the opposite of every
-- other function here. Those two attributes are what stop Postgres inlining a SQL function,
-- and inlining is what lets the planner push effective_bindings' principal filter down into
-- this query. Measured with 20k bindings at one tenant: inlined, has_scope costs the same as
-- when this query lived inside effective_bindings; as an opaque security definer call it was
-- 35x slower, because every check materialised the whole tenant's bindings first.
--
-- That is safe only because nothing but the owner can reach it. EXECUTE is revoked from
-- everyone, so it runs inside the security definer functions that call it, as the owner and
-- under their empty search_path. Every reference in it is schema-qualified regardless. Never
-- grant it: as an invoker function it would run under the caller's RLS and search_path.
create or replace function authz.bindings_in_force(p_tenant_id uuid)
    returns table (binding_id uuid, principal_id uuid, role_id uuid, source_tenant_id uuid,
                   depth integer)
    language sql
    stable
as $$
-- No name-keyed merge here: bindings never shadow. A principal can hold master's admin and
-- a child's admin at once and both are returned, deduplicated only by binding row.
select rb.id, rb.principal_id, rb.role_id, rb.tenant_id, c.depth
  from authz.tenant_chain(p_tenant_id) c
  join authz.role_bindings rb on rb.tenant_id = c.tenant_id
  join authz.roles r on r.id = rb.role_id
  join authz.principals p on p.id = rb.principal_id
  left join authz.users u on u.id = p.user_id
  left join authz.api_keys k on k.id = p.api_key_id
 where (not c.crossed or r.crosses_boundary)
   -- Soft deletion is never implicit: every revocable timestamp is filtered here, because
   -- this is the one place grants are read.
   and rb.revoked_at is null
   and (rb.expires_at is null or rb.expires_at > now())
   -- An unclaimed identity is deliberately NOT excluded: it is unreachable from a JWT
   -- anyway, and an admin view asking what a provisioned identity will hold should see it.
   -- disabled_at and deleted_at are different -- those are revocations, so they do exclude.
   and (p.kind <> 'user'
        or (u.disabled_at is null and u.deleted_at is null))
   and (p.kind <> 'api_key'
        or (k.revoked_at is null
            and (k.expires_at is null or k.expires_at > now())));
$$;

comment on function authz.bindings_in_force(uuid) is
    'Live role bindings in force at a tenant for every principal. Invoker and inlinable by design; internal only, never grant it.';


-- Bindings in force for a principal at a tenant.
create or replace function authz.effective_bindings(p_principal_id uuid, p_tenant_id uuid)
    returns table (binding_id uuid, role_id uuid, source_tenant_id uuid, depth integer)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select b.binding_id, b.role_id, b.source_tenant_id, b.depth
  from authz.bindings_in_force(p_tenant_id) b
 where b.principal_id = p_principal_id;
$$;

comment on function authz.effective_bindings(uuid, uuid) is
    'Live role bindings for a principal at a tenant, walking the ancestor chain and filtering revoked, expired and disabled grants.';


-- The authorization answer: scope names a principal holds at a tenant.
create or replace function authz.effective_scopes(p_principal_id uuid, p_tenant_id uuid)
    returns table (scope_name text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
-- Scopes come from each binding's own role_id through role_scopes -- never from whatever
-- effective_roles() resolves that role's name to at this tenant. A child defining a role
-- of the same name does not change what an already-issued grant confers.
select distinct s.name
  from authz.effective_bindings(p_principal_id, p_tenant_id) b
  join authz.role_scopes rs on rs.role_id = b.role_id
  join authz.scopes s on s.id = rs.scope_id;
$$;

comment on function authz.effective_scopes(uuid, uuid) is
    'Distinct scope names a principal holds at a tenant, resolved through each binding''s own role.';


create or replace function authz.has_scope(p_principal_id uuid, p_tenant_id uuid,
                                           p_scope text)
    returns boolean
    language sql
    stable
    security definer
    set search_path = ''
as $$
select exists (
    select 1
      from authz.effective_scopes(p_principal_id, p_tenant_id) es
     where es.scope_name = p_scope
);
$$;

comment on function authz.has_scope(uuid, uuid, text) is
    'Whether a principal holds a named scope at a tenant. The intended predicate for RLS policies.';


-- Maps an auth.users id to its principal. This is the security boundary that makes an
-- unclaimed identity inert: auth_user_id is null on such a row, so no id can match it.
--
-- Parameterized rather than JWT-bound because an adapter on a direct Postgres connection has
-- no request.jwt.claims GUC for auth.uid() to read -- it verifies the token itself and passes
-- the subject in. current_principal_id() below delegates here so the disabled/deleted/
-- unclaimed filters exist exactly once, in SQL, rather than being restated in TypeScript.
create or replace function authz.principal_for_auth_user(p_auth_user_id uuid)
    returns uuid
    language sql
    stable
    security definer
    set search_path = ''
as $$
select p.id
  from authz.users u
  join authz.principals p on p.user_id = u.id
 where u.auth_user_id = p_auth_user_id
   and u.disabled_at is null
   and u.deleted_at is null;
$$;

comment on function authz.principal_for_auth_user(uuid) is
    'The principal behind an auth.users id, or null. Null for unclaimed, disabled and deleted identities.';


-- Bridges the JWT to a principal, for RLS policies and any caller that does arrive with
-- request.jwt.claims set. Null-safe by construction: auth.uid() null yields null.
create or replace function authz.current_principal_id()
    returns uuid
    language sql
    stable
    security definer
    set search_path = ''
as $$
select authz.principal_for_auth_user((select auth.uid()));
$$;

comment on function authz.current_principal_id() is
    'The principal behind the current JWT, or null when there is none. Delegates to principal_for_auth_user.';


-- Binds a principal to a role at a tenant. The general grant primitive: invite_user layers
-- the email/identity handling on top of this, and it is the only way to grant anything to an
-- api_key principal, which has no address to invite.
create or replace function authz.grant_role(p_actor_principal_id uuid,
                                            p_principal_id uuid,
                                            p_role_id uuid,
                                            p_tenant_id uuid,
                                            p_expires_at timestamptz default null)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.grant_role(uuid, uuid, uuid, uuid, timestamptz) is
    'Binds a principal to a role at a tenant, reinstating a revoked binding if one exists. Requires authz.bindings.grant and every scope the role confers.';


-- Adds someone to a tenant, whether or not they have a Supabase account yet.
--
-- Membership is expressed only through role_bindings, so this is the add/invite path and it
-- needs no authority over authz.users: creating an unclaimed identity is a side effect of
-- granting to an address that does not have one. Removing someone is the mirror -- revoking
-- their bindings at that tenant -- and likewise never touches authz.users.
--
-- The actor is passed explicitly rather than read from the JWT. Adapters hold a service_role
-- connection where auth.uid() is null, and API-key principals never carry a JWT at all; both
-- resolve the caller themselves and pass it here. A JWT-bound wrapper defaulting to
-- authz.current_principal_id() is the overload to grant to `authenticated`, if the authz
-- schema is ever exposed. This form must not be.
create or replace function authz.invite_user(p_actor_principal_id uuid,
                                             p_tenant_id uuid,
                                             p_email text,
                                             p_role_id uuid)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.invite_user(uuid, uuid, text, uuid) is
    'Binds an email address to a role at a tenant, provisioning an unclaimed identity if that person has no account yet. Requires authz.bindings.grant and every scope the role confers.';


-- Creates a role at a tenant.
--
-- crosses_boundary is why this is a function rather than a plain insert. "You cannot grant
-- what you do not hold" bounds a grant by what the granter already has *at that tenant* --
-- but a crossing role reaches past inherit = false throughout the owner's subtree, into
-- tenants where the granter themselves cannot act. Minting one is therefore a way to create
-- reach you do not have, and it is the one escalation invite_user's rule does not close.
--
-- Requiring authz.roles.write at the master to set the flag closes it: the only crossing
-- role a tenant admin ever sees is the seeded 'admin', and granting that already demands all
-- 14 scopes including authz.users.write, which tenant_admin does not hold.
create or replace function authz.create_role(p_actor_principal_id uuid,
                                             p_tenant_id uuid,
                                             p_name text,
                                             p_description text,
                                             p_crosses_boundary boolean default false)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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

    return v_role_id;
end;
$$;

comment on function authz.create_role(uuid, uuid, text, text, boolean) is
    'Creates a role at a tenant. Ordinary roles need authz.roles.write there; setting crosses_boundary additionally requires authz.roles.write at the master tenant.';


-- Amends a role. Null arguments leave a column alone.
--
-- tenant_id is deliberately absent: moving a role between tenants changes who it applies to
-- and needs authority at both ends, which is a different operation from editing one.
create or replace function authz.update_role(p_actor_principal_id uuid,
                                             p_role_id uuid,
                                             p_name text default null,
                                             p_description text default null,
                                             p_crosses_boundary boolean default null)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
declare
    v_tenant_id uuid;
    v_current   boolean;
begin
    select r.tenant_id, r.crosses_boundary
      into v_tenant_id, v_current
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
end;
$$;

comment on function authz.update_role(uuid, uuid, text, text, boolean) is
    'Amends a role in place; null arguments leave a column unchanged. Changing crosses_boundary in either direction requires authz.roles.write at the master tenant.';


-- Attaches a scope to a role.
--
-- The companion to invite_user's rule, and the reason this is not a plain insert: role_scopes
-- is keyed by id and bindings point at role rows, so attaching a scope widens every existing
-- binding to this role -- including ones issued higher up and propagated down. An actor may
-- therefore only attach authority they already hold themselves.
create or replace function authz.add_role_scope(p_actor_principal_id uuid,
                                                p_role_id uuid,
                                                p_scope_id uuid)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.add_role_scope(uuid, uuid, uuid) is
    'Attaches a scope to a role. Requires authz.roles.write at the role''s tenant and that the actor already holds the scope being attached.';


-- Detaches a scope from a role.
create or replace function authz.remove_role_scope(p_actor_principal_id uuid,
                                                   p_role_id uuid,
                                                   p_scope_id uuid)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
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
end;
$$;

comment on function authz.remove_role_scope(uuid, uuid, uuid) is
    'Detaches a scope from a role. Requires authz.roles.write at the role''s tenant; narrowing needs no holds-it check.';


-- Whether a principal can act right now.
--
-- Note this is a *different* question from the filter inside effective_bindings, which is
-- why the two are not shared. That one asks "what would this principal hold", and lets an
-- unclaimed identity through on purpose so an admin view can see grants waiting for someone
-- who has not signed up. This asks "is somebody actually behind this principal", so an
-- unclaimed identity fails: nobody can have authenticated as one.
create or replace function authz.principal_is_active(p_principal_id uuid)
    returns boolean
    language sql
    stable
    security definer
    set search_path = ''
as $$
select exists (
    select 1
      from authz.principals p
      left join authz.users u on u.id = p.user_id
      left join authz.api_keys k on k.id = p.api_key_id
     where p.id = p_principal_id
       and (p.kind <> 'user'
            or (u.auth_user_id is not null
                and u.disabled_at is null
                and u.deleted_at is null))
       and (p.kind <> 'api_key'
            or (k.revoked_at is null
                and (k.expires_at is null or k.expires_at > now())))
);
$$;

comment on function authz.principal_is_active(uuid) is
    'Whether a principal is presently capable of acting: a claimed, enabled user or a live API key. Stricter than the filter in effective_bindings, which admits unclaimed identities.';


-- Creates a child tenant under a parent the actor administers.
--
-- Deliberately grants nothing. Bindings propagate downward, so an actor holding
-- authz.tenants.write at the parent holds it at the child the moment that child exists --
-- a binding here would be a second row conferring nothing new and one more thing to unwind
-- when their access is revoked.
--
-- inherit is not a parameter. A child created with inherit = false would immediately cut its
-- creator off unless their role crosses boundaries, which is a self-inflicted lockout;
-- opting out belongs in a later, deliberate edit.
create or replace function authz.create_tenant(p_actor_principal_id uuid,
                                               p_parent_id uuid,
                                               p_name text)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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

    return v_tenant_id;
end;
$$;

comment on function authz.create_tenant(uuid, uuid, text) is
    'Creates a child tenant under a parent where the actor holds authz.tenants.write. Grants nothing: the actor''s existing binding already reaches the new child.';


-- Creates a top-level workspace and makes the caller its administrator.
--
-- The one function here with no scope check, which is not an oversight. Every permission in
-- the model derives from a binding and somebody who has just signed up holds none, so there
-- is no scope that could gate this. The kit ships the mechanism; the consumer owns the
-- policy -- expose it for open signup, put it behind a plan or an invite, or never expose it
-- and have an operator create tenants with create_tenant instead. Nothing here bounds how
-- many workspaces a principal may create; rate limiting is the caller's problem.
--
-- A workspace is always a child of the master, because tenants_single_master_uq forbids a
-- second root. Master is the platform and its children are the customers.
create or replace function authz.create_workspace(p_actor_principal_id uuid,
                                                  p_name text)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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

    return v_tenant_id;
end;
$$;

comment on function authz.create_workspace(uuid, text) is
    'Creates a workspace under the master and self-grants tenant_admin to the caller. Has no scope check by design -- gating who may call it is the consumer''s policy decision.';


-- Amends a tenant. Null arguments leave a column alone.
--
-- The two fields answer to different authorities, and the asymmetry is the whole point.
-- Renaming is an ordinary edit needing authz.tenants.write at the tenant itself. Changing
-- inherit is not: cutting a tenant off from its parent severs the reach of everyone whose
-- authority over it comes from above, so it is gated on authz.tenants.write at the PARENT.
--
-- Without that, someone bound only at a sub-tenant could set inherit = false and escape
-- their parent's oversight while keeping their own access -- the mirror of minting a
-- crossing role. Bindings propagate downward and never upward, so anchoring on the parent
-- denies exactly that caller.
--
-- Anchoring on the parent also makes the cut self-healing: an administrator who cuts off a
-- child and thereby loses reach into it still holds authority at the parent, so they can
-- always set it back. parent_id is absent for the same reason it is absent from
-- update_role -- reparenting needs authority at both ends and is a different operation.
create or replace function authz.update_tenant(p_actor_principal_id uuid,
                                               p_tenant_id uuid,
                                               p_name text default null,
                                               p_inherit boolean default null)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
declare
    v_parent_id uuid;
    v_current   boolean;
    v_found     boolean;
begin
    select true, t.parent_id, t.inherit
      into v_found, v_parent_id, v_current
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
end;
$$;

comment on function authz.update_tenant(uuid, uuid, text, boolean) is
    'Amends a tenant; null arguments leave a column unchanged. Renaming needs authz.tenants.write at the tenant, changing inherit needs it at the parent.';


-- Revokes a role binding.
--
-- A function rather than an RLS policy because RLS cannot express it: WITH CHECK sees only
-- the new row, never the old, so "may set revoked_at and nothing else" is not writable as a
-- policy. Grants are revoked by timestamp and never deleted, so this is the only sanctioned
-- way to withdraw one.
--
-- Idempotent: revoking an already-revoked binding is a no-op rather than an error, and the
-- original revoked_at is preserved so a retry cannot quietly rewrite when access ended.
create or replace function authz.revoke_binding(p_actor_principal_id uuid,
                                                p_binding_id uuid)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
declare
    v_tenant_id  uuid;
    v_revoked_at timestamptz;
    v_found      boolean;
begin
    select true, rb.tenant_id, rb.revoked_at
      into v_found, v_tenant_id, v_revoked_at
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
end;
$$;

comment on function authz.revoke_binding(uuid, uuid) is
    'Revokes a role binding by timestamp. Requires authz.bindings.revoke at the binding''s own tenant; idempotent and never deletes.';


-- Defines a scope at a tenant.
--
-- The authz. namespace is reserved to the master. scopes is unique per (tenant_id, name) and
-- authorization resolves scopes by NAME, so a tenant defining its own 'authz.users.write'
-- would genuinely hold that permission throughout its subtree -- forging the built-in
-- vocabulary would be a direct route from authz.scopes.write to full administration. The
-- reservation is also what keeps add_role_scope's ownership clause safe.
create or replace function authz.create_scope(p_actor_principal_id uuid,
                                              p_tenant_id uuid,
                                              p_name text,
                                              p_description text default null)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.create_scope(uuid, uuid, text, text) is
    'Defines a scope at a tenant. Requires authz.scopes.write there; the reserved authz. namespace additionally requires it at the master tenant.';


-- Issues an API key. Returns the plaintext key, which is never recoverable afterwards --
-- only its SHA-256 is stored, in the same char(64) hex shape as users.email_id.
create or replace function authz.create_api_key(p_actor_principal_id uuid,
                                                p_tenant_id uuid,
                                                p_label text,
                                                p_expires_at timestamptz default null)
    returns text
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.create_api_key(uuid, uuid, text, timestamptz) is
    'Issues an API key at a tenant and returns the plaintext once. Requires authz.api_keys.write and a user principal as the actor.';


-- Resolves a presented key to its principal, or null. This is the API-key half of
-- current_principal_id(): adapters call it to turn a header into an actor they can pass to
-- the write functions, since an API key carries no JWT and auth.uid() is null for it.
create or replace function authz.verify_api_key(p_key text)
    returns uuid
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.verify_api_key(text) is
    'Resolves a presented API key to its principal id, or null if unknown, revoked or expired. Updates last_used_at.';


-- Revokes an API key by timestamp. Every binding the key's principal holds goes with it,
-- because effective_bindings filters on api_keys.revoked_at -- there is no need to unwind
-- the grants separately.
create or replace function authz.revoke_api_key(p_actor_principal_id uuid,
                                                p_api_key_id uuid)
    returns void
    language plpgsql
    security definer
    set search_path = ''
as $$
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
$$;

comment on function authz.revoke_api_key(uuid, uuid) is
    'Revokes an API key by timestamp. Requires authz.api_keys.write at the key''s tenant; idempotent.';


-- ---------------------------------------------------------------------------------------
-- Policy predicates
--
-- Every RLS policy in 002 calls one of these rather than subquerying an authz table
-- directly. A policy that reads another RLS-protected table has that table's own policies
-- applied inside it, which silently narrows the result and can recurse; routing through
-- SECURITY DEFINER functions reads past RLS and keeps each rule in one place.
-- ---------------------------------------------------------------------------------------

-- authz.users has no tenant_id, so "who may read this person" is derived through their
-- bindings: you can see someone if they hold a live binding at a tenant where you hold
-- authz.users.read. Without this an unscoped policy would let one tenant's admin enumerate
-- every address on the platform.
create or replace function authz.can_read_user(p_actor_principal_id uuid, p_user_id uuid)
    returns boolean
    language sql
    stable
    security definer
    set search_path = ''
as $$
select exists (
    select 1
      from authz.role_bindings rb
      join authz.principals p on p.id = rb.principal_id
     where p.user_id = p_user_id
       and rb.revoked_at is null
       and (rb.expires_at is null or rb.expires_at > now())
       and authz.has_scope(p_actor_principal_id, rb.tenant_id, 'authz.users.read')
);
$$;

comment on function authz.can_read_user(uuid, uuid) is
    'Whether an actor may read an authz.users row, derived through bindings since users are not tenant-scoped.';


-- A principal is readable if it is your own, or if its subject is: the person behind a user
-- principal, or the tenant behind an api_key principal.
create or replace function authz.can_read_principal(p_actor_principal_id uuid,
                                                    p_principal_id uuid)
    returns boolean
    language sql
    stable
    security definer
    set search_path = ''
as $$
select exists (
    select 1
      from authz.principals p
      left join authz.api_keys k on k.id = p.api_key_id
     where p.id = p_principal_id
       and (p.id = p_actor_principal_id
            or (p.user_id is not null
                and authz.can_read_user(p_actor_principal_id, p.user_id))
            or (k.id is not null
                and authz.has_scope(p_actor_principal_id, k.tenant_id,
                                    'authz.api_keys.read')))
);
$$;

comment on function authz.can_read_principal(uuid, uuid) is
    'Whether an actor may read a principal: their own, or one whose user or API key they can read.';


-- role_scopes has no tenant of its own; it inherits the tenant of the role it links.
create or replace function authz.role_tenant_id(p_role_id uuid)
    returns uuid
    language sql
    stable
    security definer
    set search_path = ''
as $$
select r.tenant_id from authz.roles r where r.id = p_role_id;
$$;

comment on function authz.role_tenant_id(uuid) is
    'The tenant owning a role. Lets the role_scopes policy resolve a tenant without reading authz.roles under RLS.';


-- ---------------------------------------------------------------------------------------
-- Reads
--
-- The sanctioned read path for an application, shaped like the writes: the actor is passed
-- explicitly, and each function is security definer so it reads past RLS and carries its own
-- rule. They answer the same visibility questions as the dormant policies in 002, but per
-- tenant rather than per table row, so a few of them resolve through the ancestor chain where
-- a policy on the raw row could not.
--
-- Refusal is filtering, never an exception. An actor without authority gets zero rows --
-- exactly what RLS would return -- so no read can be used to probe whether a tenant, role or
-- binding exists.
--
-- Lists page by keyset. PostgREST applies max_rows (1000 by default) to RPC results too and
-- truncates silently, so an unpaged list would quietly lose rows once it grew. Each row
-- carries page_cursor, which is the row's id followed by its sort key; pass the last row's
-- page_cursor back as p_after. An id is always 36 characters, which is what lets the two
-- halves be split without a delimiter that a name could contain. p_limit is clamped to
-- [1, 1000] and defaults to 100.
-- ---------------------------------------------------------------------------------------

-- A tenant, if the actor holds authz.tenants.read there.
create or replace function authz.get_tenant(p_actor_principal_id uuid, p_tenant_id uuid)
    returns table (tenant_id uuid, parent_id uuid, name text, inherit boolean,
                   created_at timestamptz, updated_at timestamptz)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select t.id, t.parent_id, t.name, t.inherit, t.created_at, t.updated_at
  from authz.tenants t
 where t.id = p_tenant_id
   and authz.has_scope(p_actor_principal_id, t.id, 'authz.tenants.read');
$$;

comment on function authz.get_tenant(uuid, uuid) is
    'A tenant, or no row unless the actor holds authz.tenants.read at it.';


-- The children of a tenant that the actor holds authz.tenants.read at, by name.
--
-- The authority check has a shortcut, and it is what keeps listing the master's workspaces
-- from costing one ancestor walk per workspace. A child that inherits receives every binding
-- in force at its parent, so whatever the actor holds at the parent they also hold at such a
-- child: authority at the parent, checked once, answers for every inheriting child. Only a
-- child with inherit = false needs its own check, because the cut may filter the actor out.
-- The shortcut can only ever admit a row has_scope would also admit.
create or replace function authz.list_child_tenants(p_actor_principal_id uuid,
                                                    p_parent_id uuid,
                                                    p_limit integer default 100,
                                                    p_after text default null)
    returns table (tenant_id uuid, parent_id uuid, name text, inherit boolean,
                   created_at timestamptz, updated_at timestamptz, page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select t.id, t.parent_id, t.name, t.inherit, t.created_at, t.updated_at,
       t.id::text || t.name
  from authz.tenants t
 where t.parent_id = p_parent_id
   and case
           when t.inherit
                and (select authz.has_scope(p_actor_principal_id, p_parent_id,
                                            'authz.tenants.read'))
               then true
           else authz.has_scope(p_actor_principal_id, t.id, 'authz.tenants.read')
       end
   and (p_after is null
        or (t.name, t.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by t.name, t.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_child_tenants(uuid, uuid, integer, text) is
    'Child tenants of a parent that the actor holds authz.tenants.read at, ordered by name and paged by keyset.';


-- The live bindings one principal holds, across every tenant, by tenant name.
--
-- Your own bindings are always visible, as in the role_bindings policy -- this is how a
-- person finds out which tenants they belong to. Anyone else's need authz.bindings.read
-- where the binding was made.
--
-- Membership reveals names: a binding of your own shows its tenant's and role's names even
-- without authz.tenants.read or authz.roles.read, because a tenant switcher that could not
-- name your own tenants would be useless. For another principal's bindings each name follows
-- the ordinary read scope at that tenant and is null without it.
create or replace function authz.list_principal_bindings(p_actor_principal_id uuid,
                                                         p_principal_id uuid,
                                                         p_limit integer default 100,
                                                         p_after text default null)
    returns table (binding_id uuid, principal_id uuid, tenant_id uuid, tenant_name text,
                   role_id uuid, role_name text, granted_by_principal_id uuid,
                   granted_at timestamptz, expires_at timestamptz, page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
with visible as (
    select rb.id as binding_id, rb.principal_id, rb.tenant_id,
           case
               when p_actor_principal_id = p_principal_id then t.name
               when authz.has_scope(p_actor_principal_id, rb.tenant_id,
                                    'authz.tenants.read') then t.name
           end as tenant_name,
           rb.role_id,
           case
               when p_actor_principal_id = p_principal_id then r.name
               when authz.has_scope(p_actor_principal_id, rb.tenant_id,
                                    'authz.roles.read') then r.name
           end as role_name,
           rb.granted_by_principal_id, rb.granted_at, rb.expires_at
      from authz.role_bindings rb
      join authz.tenants t on t.id = rb.tenant_id
      join authz.roles r on r.id = rb.role_id
     where rb.principal_id = p_principal_id
       and (p_actor_principal_id = p_principal_id
            or authz.has_scope(p_actor_principal_id, rb.tenant_id, 'authz.bindings.read'))
       -- Liveness comes from bindings_in_force rather than being restated. At a binding's own
       -- tenant nothing is crossed, so all that filter leaves is revoked, expired, disabled.
       and exists (
           select 1
             from authz.bindings_in_force(rb.tenant_id) b
            where b.binding_id = rb.id
       )
)
select v.*, v.binding_id::text || coalesce(v.tenant_name, '')
  from visible v
 where p_after is null
    or (coalesce(v.tenant_name, ''), v.binding_id)
       > (substr(p_after, 37), substr(p_after, 1, 36)::uuid)
 order by coalesce(v.tenant_name, ''), v.binding_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_principal_bindings(uuid, uuid, integer, text) is
    'Live bindings held by a principal: all of them for the principal itself, otherwise those at tenants where the actor holds authz.bindings.read.';


-- Who is a member of a tenant: the live bindings there, by email or API key label.
--
-- By default only bindings made AT the tenant. p_include_inherited adds every binding in force
-- there from above -- which, for any tenant under the master, includes the platform operators.
-- Each binding is shown where the actor holds authz.bindings.read at the tenant it was made,
-- or where it is the actor's own -- exactly the role_bindings policy -- so a tenant admin
-- asking for inherited bindings sees none from tenants they cannot read, and a plain member
-- sees themselves and nobody else.
--
-- Unclaimed identities are listed, with claimed = false: they are pending invites, and
-- bindings_in_force admits them deliberately. Disabled and deleted identities are not.
--
-- The detail columns are null without the matching authority where the binding was made:
-- email needs authz.users.read, role_name authz.roles.read, and an API key's label needs
-- authz.api_keys.read at the key's own tenant. Your own row always shows your email and role,
-- as in list_principal_bindings. That rule for email is narrower than can_read_user, which
-- would also admit someone readable through some other tenant. The narrower rule is checked
-- once per tenant in the chain; can_read_user costs a query per row, and the sort would force
-- it onto every row of the tenant, not just the page.
create or replace function authz.list_tenant_bindings(p_actor_principal_id uuid,
                                                      p_tenant_id uuid,
                                                      p_include_inherited boolean default false,
                                                      p_limit integer default 100,
                                                      p_after text default null)
    returns table (binding_id uuid, principal_id uuid, principal_kind text,
                   user_id uuid, email text, claimed boolean,
                   api_key_id uuid, api_key_label text,
                   role_id uuid, role_name text,
                   source_tenant_id uuid, inherited boolean,
                   granted_by_principal_id uuid, granted_at timestamptz,
                   expires_at timestamptz, page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
-- MATERIALIZED is load-bearing. A CTE referenced once is otherwise inlined into the join, and
-- then these has_scope calls run once per binding instead of once per tenant in the chain:
-- measured at 43 seconds for one page of a tenant with 20k members, against milliseconds here.
with sources as materialized (
    select c.tenant_id,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.bindings.read') as bindings_read,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.users.read') as users_read,
           authz.has_scope(p_actor_principal_id, c.tenant_id, 'authz.roles.read') as roles_read
      from authz.tenant_chain(p_tenant_id) c
     where c.depth = 0 or coalesce(p_include_inherited, false)
),
visible as (
    select b.binding_id, b.principal_id, p.kind::text as principal_kind,
           p.user_id,
           case when s.users_read or b.principal_id = p_actor_principal_id
                then u.email end as email,
           case when p.kind = 'user' then u.auth_user_id is not null end as claimed,
           p.api_key_id,
           case
               when k.id is null then null
               when authz.has_scope(p_actor_principal_id, k.tenant_id,
                                    'authz.api_keys.read') then k.label
           end as api_key_label,
           b.role_id,
           case when s.roles_read or b.principal_id = p_actor_principal_id
                then r.name end as role_name,
           b.source_tenant_id,
           b.depth > 0 as inherited,
           rb.granted_by_principal_id, rb.granted_at, rb.expires_at
      from authz.bindings_in_force(p_tenant_id) b
      join sources s on s.tenant_id = b.source_tenant_id
      join authz.role_bindings rb on rb.id = b.binding_id
      join authz.roles r on r.id = b.role_id
      join authz.principals p on p.id = b.principal_id
      left join authz.users u on u.id = p.user_id
      left join authz.api_keys k on k.id = p.api_key_id
     where s.bindings_read or b.principal_id = p_actor_principal_id
)
select v.*, v.binding_id::text || coalesce(v.email, v.api_key_label, '')
  from visible v
 where p_after is null
    or (coalesce(v.email, v.api_key_label, ''), v.binding_id)
       > (substr(p_after, 37), substr(p_after, 1, 36)::uuid)
 order by coalesce(v.email, v.api_key_label, ''), v.binding_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_tenant_bindings(uuid, uuid, boolean, integer, text) is
    'Live bindings at a tenant -- its members -- that are the actor''s own or were made where the actor holds authz.bindings.read. Optionally includes bindings inherited from above.';


-- The roles in effect at a tenant, after shadowing, if the actor holds authz.roles.read there.
--
-- Resolved rather than raw: a tenant sees the master's built-ins it inherits, flagged
-- inherited, and not the rows a nearer definition shadows. The roles policy gates each row on
-- its owning tenant instead, which would hide every inherited role from a tenant admin -- the
-- one thing a role picker has to show.
create or replace function authz.list_roles(p_actor_principal_id uuid,
                                            p_tenant_id uuid,
                                            p_limit integer default 100,
                                            p_after text default null)
    returns table (role_id uuid, name text, description text, crosses_boundary boolean,
                   source_tenant_id uuid, inherited boolean, page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select er.role_id, er.name, r.description, er.crosses_boundary, er.source_tenant_id,
       er.depth > 0, er.role_id::text || er.name
  from authz.effective_roles(p_tenant_id) er
  join authz.roles r on r.id = er.role_id
 where authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.roles.read')
   and (p_after is null
        or (er.name, er.role_id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by er.name, er.role_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_roles(uuid, uuid, integer, text) is
    'Roles in effect at a tenant after shadowing, if the actor holds authz.roles.read there.';


-- The scopes a role confers, viewed from a tenant where the actor holds authz.roles.read.
--
-- Anchored on a tenant rather than on the role's owner for the same reason as list_roles: a
-- tenant admin must be able to see what the inherited tenant_admin role contains. The role has
-- to be in effect at that tenant, or be the role of a binding in force there -- the second
-- clause covers a binding to a role a nearer definition has since shadowed, which
-- list_tenant_bindings can still show.
--
-- These are the scopes attached to this role row, which is what a binding to it confers --
-- never the scopes of whatever its name resolves to elsewhere.
create or replace function authz.list_role_scopes(p_actor_principal_id uuid,
                                                  p_tenant_id uuid,
                                                  p_role_id uuid,
                                                  p_limit integer default 100,
                                                  p_after text default null)
    returns table (scope_id uuid, name text, description text, source_tenant_id uuid,
                   page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select s.id, s.name, s.description, s.tenant_id, s.id::text || s.name
  from authz.role_scopes rs
  join authz.scopes s on s.id = rs.scope_id
 where rs.role_id = p_role_id
   and authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.roles.read')
   and (exists (select 1 from authz.effective_roles(p_tenant_id) er
                 where er.role_id = p_role_id)
        or exists (select 1 from authz.bindings_in_force(p_tenant_id) b
                    where b.role_id = p_role_id))
   and (p_after is null
        or (s.name, s.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by s.name, s.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_role_scopes(uuid, uuid, uuid, integer, text) is
    'Scopes attached to a role in effect at a tenant, if the actor holds authz.roles.read there.';


-- The scope definitions in effect at a tenant, after shadowing, if the actor holds
-- authz.scopes.read there. Resolved for the same reason as list_roles.
create or replace function authz.list_scopes(p_actor_principal_id uuid,
                                             p_tenant_id uuid,
                                             p_limit integer default 100,
                                             p_after text default null)
    returns table (scope_id uuid, name text, description text, source_tenant_id uuid,
                   inherited boolean, page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select sd.scope_id, sd.name, s.description, sd.source_tenant_id, sd.depth > 0,
       sd.scope_id::text || sd.name
  from authz.effective_scope_defs(p_tenant_id) sd
  join authz.scopes s on s.id = sd.scope_id
 where authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.scopes.read')
   and (p_after is null
        or (sd.name, sd.scope_id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by sd.name, sd.scope_id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_scopes(uuid, uuid, integer, text) is
    'Scope definitions in effect at a tenant after shadowing, if the actor holds authz.scopes.read there.';


-- The API keys issued at a tenant, revoked ones included, by label.
--
-- key_hash is never returned. It is a SHA-256 and not the key, but nothing needs it outside
-- verify_api_key, and a read path that cannot return it cannot leak it. principal_id is what
-- grant_role and list_principal_bindings take for a key.
create or replace function authz.list_api_keys(p_actor_principal_id uuid,
                                               p_tenant_id uuid,
                                               p_limit integer default 100,
                                               p_after text default null)
    returns table (api_key_id uuid, principal_id uuid, key_prefix text, label text,
                   tenant_id uuid, created_by_user_id uuid, last_used_at timestamptz,
                   expires_at timestamptz, revoked_at timestamptz, created_at timestamptz,
                   page_cursor text)
    language sql
    stable
    security definer
    set search_path = ''
as $$
select k.id, p.id, k.key_prefix, k.label, k.tenant_id, k.created_by_user_id,
       k.last_used_at, k.expires_at, k.revoked_at, k.created_at,
       k.id::text || k.label
  from authz.api_keys k
  join authz.principals p on p.api_key_id = k.id
 where k.tenant_id = p_tenant_id
   and authz.has_scope(p_actor_principal_id, p_tenant_id, 'authz.api_keys.read')
   and (p_after is null
        or (k.label, k.id) > (substr(p_after, 37), substr(p_after, 1, 36)::uuid))
 order by k.label, k.id
 limit least(greatest(coalesce(p_limit, 100), 1), 1000);
$$;

comment on function authz.list_api_keys(uuid, uuid, integer, text) is
    'API keys issued at a tenant, without key_hash, if the actor holds authz.api_keys.read there.';
