CREATE SCHEMA IF NOT EXISTS authz;

CREATE TYPE "authz"."principal_kind" AS ENUM ('user', 'api_key');

CREATE TABLE "authz"."users"
(
    "id"           uuid PRIMARY KEY                    NOT NULL,
    -- Nullable on purpose: authz.users is the identity record and may be provisioned by
    -- email before that person ever signs up. NULL means "not yet claimed" -- such a row
    -- can never be matched from a JWT, so it grants nothing until authz.claim_auth_user()
    -- links it on email confirmation. See 001_auth_kit_functions.sql.
    --
    -- ON DELETE SET NULL: deleting the Supabase account unlinks the identity instead of
    -- blocking the delete (the NO ACTION default) or cascading it away. The authz row, its
    -- bindings and its audit trail survive and the row reverts to unclaimed -- which also
    -- means those grants become re-claimable by whoever next confirms that address.
    "auth_user_id" uuid REFERENCES "auth"."users" (id) ON DELETE SET NULL,
    -- Set the first time this identity is linked and never cleared, including when the FK
    -- above nulls auth_user_id on account deletion. That asymmetry is the point: a row with
    -- claimed_at set but auth_user_id null is a retired identity, and authz.claim_auth_user()
    -- refuses to hand it to whoever next registers the address. authz.reclaim_identity() is
    -- the deliberate way back.
    "claimed_at"   timestamptz,
    "email_id"     char(64)                            NOT NULL,
    "email"        text                                NOT NULL,
    "created_at"   timestamptz DEFAULT now()           NOT NULL,
    "updated_at"   timestamptz DEFAULT now()           NOT NULL,
    "disabled_at"  timestamptz,
    "deleted_at"   timestamptz
);

CREATE TABLE "authz"."principals"
(
    "id"         uuid PRIMARY KEY          NOT NULL,
    "kind"       "authz".principal_kind    NOT NULL,
    "user_id"    uuid,
    "api_key_id" uuid,
    "created_at" timestamptz DEFAULT now() NOT NULL,
    "updated_at" timestamptz DEFAULT now() NOT NULL,
    CONSTRAINT "principals_exactly_one_of" CHECK (
        ("principals".kind = 'user' AND "principals".user_id IS NOT NULL AND "principals".api_key_id IS NULL)
            OR
        ("principals".kind = 'api_key' AND "principals".api_key_id IS NOT NULL AND "principals".user_id IS NULL)
        )
);

CREATE TABLE "authz"."tenants"
(
    "id"         uuid PRIMARY KEY          NOT NULL,
    "parent_id"  uuid REFERENCES "authz"."tenants" (id),
    "name"       text                      NOT NULL,
    "inherit"    boolean     DEFAULT true  NOT NULL,
    "created_at" timestamptz DEFAULT now() NOT NULL,
    "updated_at" timestamptz DEFAULT now() NOT NULL
);

CREATE TABLE "authz"."roles"
(
    "id"               uuid PRIMARY KEY                       NOT NULL,
    "tenant_id"        uuid REFERENCES "authz"."tenants" (id) NOT NULL,
    "name"             text                                   NOT NULL,
    "description"      text                                   NOT NULL,
    "crosses_boundary" boolean     DEFAULT false              NOT NULL,
    "created_at"       timestamptz DEFAULT now()              NOT NULL,
    "updated_at"       timestamptz DEFAULT now()              NOT NULL
);

CREATE TABLE "authz"."scopes"
(
    "id"          uuid PRIMARY KEY                     NOT NULL,
    "tenant_id"   uuid REFERENCES "authz".tenants (id) NOT NULL,
    "name"        text                                 NOT NULL,
    "description" text,
    "created_at"  timestamptz DEFAULT now()            NOT NULL,
    "updated_at"  timestamptz DEFAULT now()            NOT NULL
);

CREATE TABLE "authz"."role_scopes"
(
    "role_id"    uuid REFERENCES "authz".roles (id)  NOT NULL,
    "scope_id"   uuid REFERENCES "authz".scopes (id) NOT NULL,
    "created_at" timestamptz DEFAULT now()           NOT NULL,
    "updated_at" timestamptz DEFAULT now()           NOT NULL,
    CONSTRAINT "role_scopes_role_id_scope_id_pk" PRIMARY KEY ("role_id", "scope_id")
);

CREATE TABLE "authz"."role_bindings"
(
    "id"                      uuid PRIMARY KEY                        NOT NULL,
    "principal_id"            uuid REFERENCES "authz".principals (id) NOT NULL,
    "role_id"                 uuid REFERENCES "authz".roles (id)      NOT NULL,
    "tenant_id"               uuid REFERENCES "authz".tenants (id)    NOT NULL,
    "granted_by_principal_id" uuid REFERENCES "authz".principals (id) NOT NULL,
    "granted_at"              timestamptz DEFAULT now()               NOT NULL,
    "expires_at"              timestamptz,
    "revoked_at"              timestamptz,
    "created_at"              timestamptz DEFAULT now()               NOT NULL,
    "updated_at"              timestamptz DEFAULT now()               NOT NULL
);

CREATE TABLE "authz"."api_keys"
(
    "id"                 uuid PRIMARY KEY                     NOT NULL,
    "key_hash"           char(64)                             NOT NULL,
    "key_prefix"         text                                 NOT NULL,
    "label"              text                                 NOT NULL,
    "tenant_id"          uuid REFERENCES "authz".tenants (id) NOT NULL,
    "created_by_user_id" uuid REFERENCES "authz".users (id)   NOT NULL,
    "last_used_at"       timestamptz,
    "expires_at"         timestamptz,
    "revoked_at"         timestamptz,
    "created_at"         timestamptz DEFAULT now()            NOT NULL,
    "updated_at"         timestamptz DEFAULT now()            NOT NULL
);

CREATE TABLE "authz"."audit_logs"
(
    "id"                 uuid PRIMARY KEY          NOT NULL,
    "actor_principal_id" uuid REFERENCES "authz".principals (id),
    "actor_kind"         text,
    "request_id"         text                      NOT NULL,
    "method"             text                      NOT NULL,
    "route"              text                      NOT NULL,
    "action"             text                      NOT NULL,
    "target_type"        text                      NOT NULL,
    "target_id"          uuid,
    "tenant_id"          uuid REFERENCES "authz".tenants (id),
    "before"             jsonb,
    "after"              jsonb,
    "ip"                 text,
    "user_agent"         text,
    "created_at"         timestamptz DEFAULT now() NOT NULL,
    "updated_at"         timestamptz DEFAULT now() NOT NULL
);

CREATE UNIQUE INDEX "api_keys_key_prefix_uq" ON "authz"."api_keys" using btree ("key_prefix");
CREATE INDEX "api_keys_tenant_id_idx" ON "authz"."api_keys" using btree ("tenant_id");
CREATE UNIQUE INDEX "principals_user_id_uq" ON "authz"."principals" using btree ("user_id");
CREATE UNIQUE INDEX "principals_api_key_id_uq" ON "authz"."principals" using btree ("api_key_id");
CREATE UNIQUE INDEX "role_bindings_principal_role_tenant_uq"
    ON "authz"."role_bindings" using btree ("principal_id", "role_id", "tenant_id");
CREATE INDEX "role_bindings_principal_id_idx" ON "authz"."role_bindings" using btree ("principal_id");
CREATE INDEX "role_bindings_role_id_idx" ON "authz"."role_bindings" using btree ("role_id");
CREATE INDEX "role_bindings_tenant_id_idx" ON "authz"."role_bindings" using btree ("tenant_id");
CREATE INDEX "role_scopes_role_id_idx" ON "authz"."role_scopes" using btree ("role_id");
CREATE INDEX "role_scopes_scope_id_idx" ON "authz"."role_scopes" using btree ("scope_id");
CREATE UNIQUE INDEX "roles_tenant_name_uq" ON "authz"."roles" using btree ("tenant_id", "name");
CREATE INDEX "roles_tenant_id_idx" ON "authz"."roles" using btree ("tenant_id");
CREATE UNIQUE INDEX "scopes_tenant_id_name_uq" ON "authz"."scopes" using btree ("tenant_id", "name");
CREATE INDEX "scopes_tenant_id_idx" ON "authz"."scopes" using btree ("tenant_id");
CREATE INDEX "tenants_parent_id_idx" ON "authz"."tenants" using btree ("parent_id");
CREATE UNIQUE INDEX "tenants_single_master_uq" ON "authz"."tenants" (("parent_id" IS NULL))
    WHERE "parent_id" IS NULL;
CREATE UNIQUE INDEX "users_email_id_uq" ON "authz"."users" using btree ("email_id");
-- Unique rather than plain: at most one authz user may be linked to a given auth user.
-- Postgres treats NULLs as distinct in a unique index, so any number of provisioned-but-
-- unclaimed rows coexist while claimed rows stay one-to-one with auth.users.
CREATE UNIQUE INDEX "users_auth_user_id_uq" ON "authz"."users" using btree ("auth_user_id");
CREATE INDEX "users_disabled_at_idx" ON "authz"."users" using btree ("disabled_at");
CREATE INDEX "users_deleted_at_idx" ON "authz"."users" using btree ("deleted_at");
CREATE INDEX "audit_log_target_idx" ON "authz"."audit_logs" USING btree ("target_type", "target_id", "created_at");
CREATE INDEX "audit_log_actor_idx" ON "authz"."audit_logs" USING btree ("actor_principal_id", "created_at")
    WHERE "authz"."audit_logs"."actor_principal_id" IS NOT NULL;
CREATE INDEX "audit_log_tenant_idx" ON "authz"."audit_logs" USING btree ("tenant_id", "created_at")
    WHERE "authz"."audit_logs"."tenant_id" IS NOT NULL;
CREATE INDEX "audit_log_created_at_idx" ON "authz"."audit_logs" USING btree ("created_at");
CREATE INDEX "audit_log_request_id_idx" ON "authz"."audit_logs" USING btree ("request_id");

ALTER TABLE "authz"."users"
    enable row level security;
ALTER TABLE "authz"."tenants"
    enable row level security;
ALTER TABLE "authz"."principals"
    enable row level security;
ALTER TABLE "authz"."roles"
    enable row level security;
ALTER TABLE "authz"."scopes"
    enable row level security;
ALTER TABLE "authz"."role_scopes"
    enable row level security;
ALTER TABLE "authz"."role_bindings"
    enable row level security;
ALTER TABLE "authz"."api_keys"
    enable row level security;
ALTER TABLE "authz"."audit_logs"
    enable row level security;
