alter table "authz"."users" drop constraint "users_auth_user_id_fkey";

alter table "authz"."users" add constraint "users_auth_user_id_fkey" FOREIGN KEY (auth_user_id) REFERENCES auth.users(id) ON DELETE SET NULL not valid;

alter table "authz"."users" validate constraint "users_auth_user_id_fkey";

CREATE TRIGGER on_auth_user_confirmed AFTER INSERT OR UPDATE OF email, email_confirmed_at ON auth.users FOR EACH ROW EXECUTE FUNCTION authz.claim_auth_user();


