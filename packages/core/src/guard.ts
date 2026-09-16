import type { AuthzContext } from "./context.js";
import {
    ForbiddenError,
    TenantRequiredError,
    UnauthenticatedError,
} from "./http-errors.js";
import { isUuid } from "./uuid.js";

/** Decides one guard against a principal that exists and a tenant that is a uuid. Throws to deny. */
export type GuardCheck = (context: AuthzContext, tenantId: string) => Promise<void>;

/**
 * The guard every framework binding runs. **The order here is the whole guard**, and it lives in
 * one place so the bindings cannot drift apart. Every branch either denies or continues; none
 * skips:
 *
 *   1. no principal, no credential presented  -> 401
 *   2. no principal, credential presented     -> 403 (open question 1: authenticated, zero authority)
 *   3. tenant unresolvable or not a uuid      -> 400
 *   4. the check                              -> 403 on a missing scope
 *
 * The principal is checked before the tenant is resolved, so an anonymous request never reaches
 * the tenant hook. A missing context -- the authentication step never ran -- is the binding's to
 * detect, because the fix it names is framework-specific; it must throw rather than call this.
 *
 * **Both 403 branches record a denied audit row, and only those two.** A 401 is not an
 * authorization outcome -- nobody was refused anything, the request simply did not say who it
 * was -- and logging it would turn every unauthenticated probe into a write. A 400 is a
 * malformed request, not a refusal. The row is awaited before the error propagates, so a denial
 * that reached the caller is a denial that reached the log; this is an error path, where the
 * extra round trip is worth that guarantee. Turn it off with `audit: { denials: false }`.
 */
export async function enforceGuard(
    context: AuthzContext,
    resolveTenant: () => unknown,
    check: GuardCheck,
): Promise<void> {
    if (context.principalId === null) {
        if (!context.credentialPresented) {
            throw new UnauthenticatedError();
        }

        const denial = new ForbiddenError(
            "credential verified but maps to no authz identity",
        );

        // No tenant: the guard refuses here before resolving one, so there is nothing to anchor
        // the row to. It is a platform-level row, readable with authz.audit.read at the master.
        await context.recordDenial({
            action: "authenticate",
            targetType: "request",
            reason: denial.message,
        });

        throw denial;
    }

    const tenantId = await resolveTenant();

    if (!isUuid(tenantId)) {
        throw new TenantRequiredError();
    }

    try {
        await check(context, tenantId);
    } catch (error) {
        if (error instanceof ForbiddenError) {
            await context.recordDenial({
                tenantId,
                action: "authorize",
                targetType: "tenant",
                targetId: tenantId,
                reason: error.message,
            });
        }

        throw error;
    }
}

export function checkScope(scope: string): GuardCheck {
    return async (context, tenantId) => {
        if (!(await context.has(tenantId, scope))) {
            throw new ForbiddenError(`missing scope ${scope}`, scope);
        }
    };
}

/** One `effective_scopes` round trip regardless of how many scopes are listed. */
export function checkAllScopes(required: readonly string[]): GuardCheck {
    return async (context, tenantId) => {
        const held = await context.scopes(tenantId);
        const missing = required.filter(scope => !held.has(scope));

        if (missing.length > 0) {
            throw new ForbiddenError(`missing scope ${missing[0]}`, missing[0]);
        }
    };
}

export function checkAnyScope(accepted: readonly string[]): GuardCheck {
    return async (context, tenantId) => {
        const held = await context.scopes(tenantId);

        if (!accepted.some(scope => held.has(scope))) {
            throw new ForbiddenError(`missing all of: ${accepted.join(", ")}`);
        }
    };
}
