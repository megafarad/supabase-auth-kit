import { AuthzDeniedError } from "@sirhc77/supabase-auth-kit-core";
import fastify, { type FastifyInstance } from "fastify";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
    createFastifyAuthKit,
    tenantFromBody,
    tenantFromParam,
    type FastifyAuthKit,
} from "../src/index.js";

const TENANT = "22222222-2222-4222-8222-222222222222";
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const AUTH_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

interface Stub {
    /** null means "this token maps to no authz identity". */
    principal?: string | null;
    scopes?: string[];
    verify?: string | null;
}

function build(stub: Stub) {
    const audited: unknown[][] = [];

    const query = vi.fn(async (sql: string, params: readonly unknown[]) => {
        if (sql.includes("principal_for_auth_user")) {
            return [{ result: stub.principal ?? null }];
        }

        if (sql.includes("verify_api_key")) {
            return [{ result: stub.principal ?? null }];
        }

        if (sql.includes("effective_scopes")) {
            return (stub.scopes ?? []).map(s => ({ scope_name: s }));
        }

        if (sql.includes("log_audit")) {
            audited.push([...params]);

            return [{ result: "audit-row" }];
        }

        throw new Error(`unexpected sql: ${sql}`);
    });

    const auth: FastifyAuthKit = createFastifyAuthKit({
        query,
        verifyBearer: async () => (stub.verify === undefined ? AUTH_USER : stub.verify),
        resolveTenant: tenantFromParam("tenantId"),
    });

    const handler = vi.fn(async () => ({ ok: true }));

    return { auth, query, handler, audited };
}

const effectiveScopeCalls = (query: ReturnType<typeof build>["query"]) =>
    query.mock.calls.filter(c => String(c[0]).includes("effective_scopes"));

describe("plugin", () => {
    let app: FastifyInstance;

    beforeEach(() => {
        app = fastify();
    });

    afterEach(async () => {
        await app.close();
    });

    // The route lives on the root instance, so this also proves fastify-plugin let the
    // hook and decorator escape the plugin's own encapsulation context.
    it("allows a principal holding the scope", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.read"],
        });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(200);
        expect(handler).toHaveBeenCalledOnce();
    });

    it("authenticates an API key", async () => {
        const { auth, handler, query } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.read"],
        });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { "x-api-key": "sak_x_y" },
        });

        expect(res.statusCode).toBe(200);
        expect(
            query.mock.calls.filter(c => String(c[0]).includes("verify_api_key")),
        ).toHaveLength(1);
    });

    it("returns 403 and never runs the handler when the scope is absent", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["something.else"],
        });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(403);
        expect(res.json().code).toBe("forbidden");
        expect(handler).not.toHaveBeenCalled();
    });

    it("returns 401 when no credential was presented", async () => {
        const { auth, handler } = build({ principal: PRINCIPAL });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({ url: `/t/${TENANT}/x` });

        expect(res.statusCode).toBe(401);
        expect(res.json().code).toBe("unauthenticated");
        expect(handler).not.toHaveBeenCalled();
    });

    /**
     * Open question 1 at the HTTP layer: a token that verified against the project's own JWKS
     * but maps to no authz identity. Must be a clean 403 -- not a 500, and not a pass.
     */
    it("returns 403, not 500, for a verified token with no authz identity", async () => {
        const { auth, handler } = build({
            principal: null,
            verify: AUTH_USER,
        });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(403);
        expect(res.json().code).toBe("forbidden");
        expect(handler).not.toHaveBeenCalled();
    });

    it("returns 400 for an unresolvable tenant, without querying", async () => {
        const { auth, handler, query } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.read"],
        });

        await app.register(auth.plugin);
        // Route param is not a uuid, so the resolver yields nothing.
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: "/t/not-a-uuid/x",
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(400);
        expect(res.json().code).toBe("tenant_required");
        expect(handler).not.toHaveBeenCalled();
        expect(effectiveScopeCalls(query)).toHaveLength(0);
    });

    // A wiring bug must not be indistinguishable from an allow.
    it("returns 500 when the plugin was never registered", async () => {
        const { auth, handler } = build({ principal: PRINCIPAL });

        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(500);
        expect(res.json().code).toBe("middleware_missing");
        expect(handler).not.toHaveBeenCalled();
    });

    // The same bug, reached through encapsulation: the plugin covers a child context only.
    it("returns 500 on a route outside the plugin's context", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.read"],
        });

        await app.register(async child => {
            await child.register(auth.plugin);
        });
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(500);
        expect(res.json().code).toBe("middleware_missing");
        expect(handler).not.toHaveBeenCalled();
    });

    it("routes a rejected query to the error handler", async () => {
        const auth = createFastifyAuthKit({
            query: async () => {
                throw new Error("connection reset");
            },
            verifyBearer: async () => AUTH_USER,
            resolveTenant: tenantFromParam("tenantId"),
        });

        const handler = vi.fn(async () => ({}));

        await app.register(auth.plugin);
        app.setErrorHandler(async (error, _request, reply) =>
            reply.code(599).send({ message: (error as Error).message }),
        );
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(599);
        expect(res.json().message).toBe("connection reset");
        expect(handler).not.toHaveBeenCalled();
    });

    it("makes one effective_scopes round trip for several scope checks", async () => {
        const { auth, query, handler } = build({
            principal: PRINCIPAL,
            scopes: ["a", "b", "c"],
        });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireAllScopes(["a", "b", "c"]) },
            handler,
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(200);
        expect(effectiveScopeCalls(query)).toHaveLength(1);
    });

    it("binds the request's principal to the write API, and null when there is none", async () => {
        const { auth } = build({ principal: PRINCIPAL, scopes: [] });
        const seen: Array<string | null> = [];

        await app.register(auth.plugin);
        app.get("/probe", async request => {
            seen.push(request.authKit?.as ? "bound" : null);

            return {};
        });

        await app.inject({ url: "/probe", headers: { authorization: "Bearer tok" } });
        await app.inject({ url: "/probe" });

        expect(seen).toEqual(["bound", null]);
    });

    // Guard errors carry `status` and `code`, which the default handler honours unaided.
    it("renders guard errors with Fastify's default error handler", async () => {
        const { auth } = build({ principal: PRINCIPAL, scopes: [] });

        await app.register(auth.plugin);
        app.get(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            async () => ({}),
        );

        const res = await app.inject({
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({
            statusCode: 403,
            code: "forbidden",
            error: "Forbidden",
            message: "missing scope authz.roles.read",
        });
    });

    it("errorHandler maps a write-API denial to 403", async () => {
        const { auth } = build({ principal: PRINCIPAL });

        await app.register(auth.plugin);
        app.setErrorHandler(auth.errorHandler);
        app.post("/write", async () => {
            throw new AuthzDeniedError("not allowed", "P0001");
        });

        const res = await app.inject({ method: "POST", url: "/write" });

        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({
            statusCode: 403,
            code: "forbidden",
            error: "Forbidden",
        });
    });

    it("errorHandler passes foreign errors to the parent handler untouched", async () => {
        const { auth } = build({ principal: PRINCIPAL });

        await app.register(auth.plugin);
        app.setErrorHandler(auth.errorHandler);
        app.get("/teapot", async () => {
            throw Object.assign(new Error("short and stout"), { statusCode: 418 });
        });

        const res = await app.inject({ url: "/teapot" });

        expect(res.statusCode).toBe(418);
        expect(res.json().message).toBe("short and stout");
    });

    it("resolves a tenant from the body at preHandler", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.write"],
        });

        await app.register(auth.plugin);
        app.post(
            "/roles",
            {
                preHandler: auth.requireScope("authz.roles.write", {
                    resolveTenant: tenantFromBody("tenantId"),
                }),
            },
            handler,
        );

        const res = await app.inject({
            method: "POST",
            url: "/roles",
            headers: { authorization: "Bearer tok" },
            payload: { tenantId: TENANT },
        });

        expect(res.statusCode).toBe(200);
        expect(handler).toHaveBeenCalledOnce();
    });

    // At onRequest the body is not parsed yet: that must be a 400, never an allow.
    it("fails closed on a body tenant read at onRequest", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["authz.roles.write"],
        });

        await app.register(auth.plugin);
        app.post(
            "/roles",
            {
                onRequest: auth.requireScope("authz.roles.write", {
                    resolveTenant: tenantFromBody("tenantId"),
                }),
            },
            handler,
        );

        const res = await app.inject({
            method: "POST",
            url: "/roles",
            headers: { authorization: "Bearer tok" },
            payload: { tenantId: TENANT },
        });

        expect(res.statusCode).toBe(400);
        expect(res.json().code).toBe("tenant_required");
        expect(handler).not.toHaveBeenCalled();
    });
});

/**
 * The route these exist for: `create_workspace` requires no scope at any tenant, and a
 * `POST /workspaces` request names none, so `requireScope` cannot guard it -- the last test here
 * is the proof, and the reason the hook is not just a faster guard.
 */
describe("requireIdentity on Fastify", () => {
    let app: FastifyInstance;

    beforeEach(() => {
        app = fastify();
    });

    afterEach(async () => {
        await app.close();
    });

    it("allows any principal, without an effective_scopes round trip", async () => {
        const { auth, handler, query } = build({ principal: PRINCIPAL, scopes: [] });

        await app.register(auth.plugin);
        app.post("/workspaces", { onRequest: auth.requireIdentity() }, handler);

        const res = await app.inject({
            method: "POST",
            url: "/workspaces",
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(200);
        expect(handler).toHaveBeenCalledOnce();
        // Holding no scope at all is fine here: SQL decides, and it needs no tenant to do it.
        expect(effectiveScopeCalls(query)).toHaveLength(0);
    });

    it("returns 401 when no credential was presented", async () => {
        const { auth, handler, audited } = build({ principal: PRINCIPAL });

        await app.register(auth.plugin);
        app.post("/workspaces", { onRequest: auth.requireIdentity() }, handler);

        const res = await app.inject({ method: "POST", url: "/workspaces" });

        expect(res.statusCode).toBe(401);
        expect(res.json().code).toBe("unauthenticated");
        expect(handler).not.toHaveBeenCalled();
        expect(audited).toHaveLength(0);
    });

    it("returns 403, not 500, for a verified token with no authz identity", async () => {
        const { auth, handler, audited } = build({ principal: null, verify: AUTH_USER });

        await app.register(auth.plugin);
        app.post("/workspaces", { onRequest: auth.requireIdentity() }, handler);

        const res = await app.inject({
            method: "POST",
            url: "/workspaces",
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(403);
        expect(res.json().code).toBe("forbidden");
        expect(handler).not.toHaveBeenCalled();
        // Recorded with no tenant, exactly as enforceGuard's own second branch records it.
        expect(audited).toHaveLength(1);
        expect(audited[0]).toEqual(expect.arrayContaining(["authenticate", "request"]));
    });

    // A wiring bug must not be indistinguishable from an allow here either.
    it("returns 500 when the plugin was never registered", async () => {
        const { auth, handler } = build({ principal: PRINCIPAL });

        app.post("/workspaces", { onRequest: auth.requireIdentity() }, handler);

        const res = await app.inject({
            method: "POST",
            url: "/workspaces",
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(500);
        expect(res.json().code).toBe("middleware_missing");
        expect(handler).not.toHaveBeenCalled();
    });

    // Why the hook exists at all: the same route guarded by scope is a 400 for everyone,
    // because there is no tenant in the request for the resolver to find.
    it("guards a route requireScope cannot: no tenant to resolve", async () => {
        const { auth, handler } = build({
            principal: PRINCIPAL,
            scopes: ["authz.tenants.write"],
        });

        await app.register(auth.plugin);
        app.post(
            "/scoped-workspaces",
            { onRequest: auth.requireScope("authz.tenants.write") },
            handler,
        );

        const res = await app.inject({
            method: "POST",
            url: "/scoped-workspaces",
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(400);
        expect(res.json().code).toBe("tenant_required");
        expect(handler).not.toHaveBeenCalled();
    });
});

describe("audit context on Fastify", () => {
    let app: FastifyInstance;

    beforeEach(() => {
        app = fastify();
    });

    afterEach(async () => {
        await app.close();
    });

    it("records a refused request against the matched route pattern", async () => {
        const { auth, handler, audited } = build({ principal: PRINCIPAL, scopes: [] });

        await app.register(auth.plugin);
        app.post(
            "/t/:tenantId/x",
            { onRequest: auth.requireScope("authz.roles.read") },
            handler,
        );

        const res = await app.inject({
            method: "POST",
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok", "user-agent": "vitest" },
        });

        expect(res.statusCode).toBe(403);
        expect(handler).not.toHaveBeenCalled();
        expect(audited).toHaveLength(1);

        const context = audited[0]?.at(-1) as Record<string, string>;

        expect(context).toMatchObject({
            method: "POST",
            user_agent: "vitest",
            // The pattern, not the path: audit rows group by route rather than by every
            // distinct tenant id, which is what Express cannot give.
            route: "/t/:tenantId/x",
        });

        // Fastify's own request id, so the row correlates with its logs without a header.
        expect(context["request_id"]).toBeTruthy();
    });

    it("records a credential that maps to no identity, with no tenant", async () => {
        const { auth, handler, audited } = build({ principal: null });

        await app.register(auth.plugin);
        app.get("/t/:tenantId/x", { onRequest: auth.requireScope("x") }, handler);

        const res = await app.inject({
            method: "GET",
            url: `/t/${TENANT}/x`,
            headers: { authorization: "Bearer tok" },
        });

        expect(res.statusCode).toBe(403);
        expect(audited).toHaveLength(1);
        // No principal to bind and no tenant resolved yet: a platform-level row.
        expect(audited[0]).toContain("authenticate");
        expect(audited[0]).not.toContain(TENANT);
    });

    it("records nothing when the request presented no credential", async () => {
        const { auth, handler, audited } = build({ principal: PRINCIPAL, scopes: [] });

        await app.register(auth.plugin);
        app.get("/t/:tenantId/x", { onRequest: auth.requireScope("x") }, handler);

        const res = await app.inject({ method: "GET", url: `/t/${TENANT}/x` });

        expect(res.statusCode).toBe(401);
        expect(audited).toHaveLength(0);
    });
});
