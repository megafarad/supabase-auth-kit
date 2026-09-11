create schema if not exists "authz";

create type "authz"."principal_kind" as enum ('user', 'api_key');


  create table "authz"."api_keys" (
    "id" uuid not null,
    "key_hash" character(64) not null,
    "key_prefix" text not null,
    "label" text not null,
    "tenant_id" uuid not null,
    "created_by_user_id" uuid not null,
    "last_used_at" timestamp with time zone,
    "expires_at" timestamp with time zone,
    "revoked_at" timestamp with time zone,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."api_keys" enable row level security;


  create table "authz"."audit_logs" (
    "id" uuid not null,
    "actor_principal_id" uuid,
    "actor_kind" text,
    "request_id" text not null,
    "method" text not null,
    "route" text not null,
    "action" text not null,
    "target_type" text not null,
    "target_id" uuid,
    "tenant_id" uuid,
    "before" jsonb,
    "after" jsonb,
    "ip" text,
    "user_agent" text,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."audit_logs" enable row level security;


  create table "authz"."principals" (
    "id" uuid not null,
    "kind" authz.principal_kind not null,
    "user_id" uuid,
    "api_key_id" uuid,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."principals" enable row level security;


  create table "authz"."role_bindings" (
    "id" uuid not null,
    "principal_id" uuid not null,
    "role_id" uuid not null,
    "tenant_id" uuid not null,
    "granted_by_principal_id" uuid not null,
    "granted_at" timestamp with time zone not null default now(),
    "expires_at" timestamp with time zone,
    "revoked_at" timestamp with time zone,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."role_bindings" enable row level security;


  create table "authz"."role_scopes" (
    "role_id" uuid not null,
    "scope_id" uuid not null,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."role_scopes" enable row level security;


  create table "authz"."roles" (
    "id" uuid not null,
    "tenant_id" uuid not null,
    "name" text not null,
    "description" text not null,
    "crosses_boundary" boolean not null default false,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."roles" enable row level security;


  create table "authz"."scopes" (
    "id" uuid not null,
    "tenant_id" uuid not null,
    "name" text not null,
    "description" text,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."scopes" enable row level security;


  create table "authz"."tenants" (
    "id" uuid not null,
    "parent_id" uuid,
    "name" text not null,
    "inherit" boolean not null default true,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now()
      );


alter table "authz"."tenants" enable row level security;


  create table "authz"."users" (
    "id" uuid not null,
    "auth_user_id" uuid not null,
    "email_id" character(64) not null,
    "email" text not null,
    "created_at" timestamp with time zone not null default now(),
    "updated_at" timestamp with time zone not null default now(),
    "disabled_at" timestamp with time zone,
    "deleted_at" timestamp with time zone
      );


alter table "authz"."users" enable row level security;

CREATE UNIQUE INDEX api_keys_key_prefix_uq ON authz.api_keys USING btree (key_prefix);

CREATE UNIQUE INDEX api_keys_pkey ON authz.api_keys USING btree (id);

CREATE INDEX api_keys_tenant_id_idx ON authz.api_keys USING btree (tenant_id);

CREATE INDEX audit_log_actor_idx ON authz.audit_logs USING btree (actor_principal_id, created_at) WHERE (actor_principal_id IS NOT NULL);

CREATE INDEX audit_log_created_at_idx ON authz.audit_logs USING btree (created_at);

CREATE INDEX audit_log_request_id_idx ON authz.audit_logs USING btree (request_id);

CREATE INDEX audit_log_target_idx ON authz.audit_logs USING btree (target_type, target_id, created_at);

CREATE INDEX audit_log_tenant_idx ON authz.audit_logs USING btree (tenant_id, created_at) WHERE (tenant_id IS NOT NULL);

CREATE UNIQUE INDEX audit_logs_pkey ON authz.audit_logs USING btree (id);

CREATE UNIQUE INDEX principals_api_key_id_uq ON authz.principals USING btree (api_key_id);

CREATE UNIQUE INDEX principals_pkey ON authz.principals USING btree (id);

CREATE UNIQUE INDEX principals_user_id_uq ON authz.principals USING btree (user_id);

CREATE UNIQUE INDEX role_bindings_pkey ON authz.role_bindings USING btree (id);

CREATE INDEX role_bindings_principal_id_idx ON authz.role_bindings USING btree (principal_id);

CREATE UNIQUE INDEX role_bindings_principal_role_tenant_uq ON authz.role_bindings USING btree (principal_id, role_id, tenant_id);

CREATE INDEX role_bindings_role_id_idx ON authz.role_bindings USING btree (role_id);

CREATE INDEX role_bindings_tenant_id_idx ON authz.role_bindings USING btree (tenant_id);

CREATE INDEX role_scopes_role_id_idx ON authz.role_scopes USING btree (role_id);

CREATE UNIQUE INDEX role_scopes_role_id_scope_id_pk ON authz.role_scopes USING btree (role_id, scope_id);

CREATE INDEX role_scopes_scope_id_idx ON authz.role_scopes USING btree (scope_id);

CREATE UNIQUE INDEX roles_pkey ON authz.roles USING btree (id);

CREATE INDEX roles_tenant_id_idx ON authz.roles USING btree (tenant_id);

CREATE UNIQUE INDEX roles_tenant_name_uq ON authz.roles USING btree (tenant_id, name);

CREATE UNIQUE INDEX scopes_pkey ON authz.scopes USING btree (id);

CREATE INDEX scopes_tenant_id_idx ON authz.scopes USING btree (tenant_id);

CREATE UNIQUE INDEX scopes_tenant_id_name_uq ON authz.scopes USING btree (tenant_id, name);

CREATE INDEX tenants_parent_id_idx ON authz.tenants USING btree (parent_id);

CREATE UNIQUE INDEX tenants_pkey ON authz.tenants USING btree (id);

CREATE UNIQUE INDEX tenants_single_master_uq ON authz.tenants USING btree (((parent_id IS NULL))) WHERE (parent_id IS NULL);

CREATE INDEX users_auth_user_id_idx ON authz.users USING btree (auth_user_id);

CREATE INDEX users_deleted_at_idx ON authz.users USING btree (deleted_at);

CREATE INDEX users_disabled_at_idx ON authz.users USING btree (disabled_at);

CREATE UNIQUE INDEX users_email_id_uq ON authz.users USING btree (email_id);

CREATE UNIQUE INDEX users_pkey ON authz.users USING btree (id);

alter table "authz"."api_keys" add constraint "api_keys_pkey" PRIMARY KEY using index "api_keys_pkey";

alter table "authz"."audit_logs" add constraint "audit_logs_pkey" PRIMARY KEY using index "audit_logs_pkey";

alter table "authz"."principals" add constraint "principals_pkey" PRIMARY KEY using index "principals_pkey";

alter table "authz"."role_bindings" add constraint "role_bindings_pkey" PRIMARY KEY using index "role_bindings_pkey";

alter table "authz"."role_scopes" add constraint "role_scopes_role_id_scope_id_pk" PRIMARY KEY using index "role_scopes_role_id_scope_id_pk";

alter table "authz"."roles" add constraint "roles_pkey" PRIMARY KEY using index "roles_pkey";

alter table "authz"."scopes" add constraint "scopes_pkey" PRIMARY KEY using index "scopes_pkey";

alter table "authz"."tenants" add constraint "tenants_pkey" PRIMARY KEY using index "tenants_pkey";

alter table "authz"."users" add constraint "users_pkey" PRIMARY KEY using index "users_pkey";

alter table "authz"."api_keys" add constraint "api_keys_created_by_user_id_fkey" FOREIGN KEY (created_by_user_id) REFERENCES authz.users(id) not valid;

alter table "authz"."api_keys" validate constraint "api_keys_created_by_user_id_fkey";

alter table "authz"."api_keys" add constraint "api_keys_tenant_id_fkey" FOREIGN KEY (tenant_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."api_keys" validate constraint "api_keys_tenant_id_fkey";

alter table "authz"."audit_logs" add constraint "audit_logs_actor_principal_id_fkey" FOREIGN KEY (actor_principal_id) REFERENCES authz.principals(id) not valid;

alter table "authz"."audit_logs" validate constraint "audit_logs_actor_principal_id_fkey";

alter table "authz"."audit_logs" add constraint "audit_logs_tenant_id_fkey" FOREIGN KEY (tenant_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."audit_logs" validate constraint "audit_logs_tenant_id_fkey";

alter table "authz"."principals" add constraint "principals_exactly_one_of" CHECK ((((kind = 'user'::authz.principal_kind) AND (user_id IS NOT NULL) AND (api_key_id IS NULL)) OR ((kind = 'api_key'::authz.principal_kind) AND (api_key_id IS NOT NULL) AND (user_id IS NULL)))) not valid;

alter table "authz"."principals" validate constraint "principals_exactly_one_of";

alter table "authz"."role_bindings" add constraint "role_bindings_granted_by_principal_id_fkey" FOREIGN KEY (granted_by_principal_id) REFERENCES authz.principals(id) not valid;

alter table "authz"."role_bindings" validate constraint "role_bindings_granted_by_principal_id_fkey";

alter table "authz"."role_bindings" add constraint "role_bindings_principal_id_fkey" FOREIGN KEY (principal_id) REFERENCES authz.principals(id) not valid;

alter table "authz"."role_bindings" validate constraint "role_bindings_principal_id_fkey";

alter table "authz"."role_bindings" add constraint "role_bindings_role_id_fkey" FOREIGN KEY (role_id) REFERENCES authz.roles(id) not valid;

alter table "authz"."role_bindings" validate constraint "role_bindings_role_id_fkey";

alter table "authz"."role_bindings" add constraint "role_bindings_tenant_id_fkey" FOREIGN KEY (tenant_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."role_bindings" validate constraint "role_bindings_tenant_id_fkey";

alter table "authz"."role_scopes" add constraint "role_scopes_role_id_fkey" FOREIGN KEY (role_id) REFERENCES authz.roles(id) not valid;

alter table "authz"."role_scopes" validate constraint "role_scopes_role_id_fkey";

alter table "authz"."role_scopes" add constraint "role_scopes_scope_id_fkey" FOREIGN KEY (scope_id) REFERENCES authz.scopes(id) not valid;

alter table "authz"."role_scopes" validate constraint "role_scopes_scope_id_fkey";

alter table "authz"."roles" add constraint "roles_tenant_id_fkey" FOREIGN KEY (tenant_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."roles" validate constraint "roles_tenant_id_fkey";

alter table "authz"."scopes" add constraint "scopes_tenant_id_fkey" FOREIGN KEY (tenant_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."scopes" validate constraint "scopes_tenant_id_fkey";

alter table "authz"."tenants" add constraint "tenants_parent_id_fkey" FOREIGN KEY (parent_id) REFERENCES authz.tenants(id) not valid;

alter table "authz"."tenants" validate constraint "tenants_parent_id_fkey";

alter table "authz"."users" add constraint "users_auth_user_id_fkey" FOREIGN KEY (auth_user_id) REFERENCES auth.users(id) not valid;

alter table "authz"."users" validate constraint "users_auth_user_id_fkey";


