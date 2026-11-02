---
"@sirhc77/supabase-auth-kit-core": minor
"@sirhc77/supabase-auth-kit-express": minor
"@sirhc77/supabase-auth-kit-fastify": minor
---

Support requiring TOTP on routes. The `aal` claim of a Supabase access token now reaches the guards: `requireAal2()` and `{ aal2: true }` on the scope guards answer 403 `mfa_required` to a user below aal2, and refuse API keys unless `allowApiKeys` is set. A custom `verifyBearer` may return `{ authUserId, aal }`; a bare ID still works but is refused by these guards.
