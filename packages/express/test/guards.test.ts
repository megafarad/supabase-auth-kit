import type { Express } from "express";
import express5 from "express";
// eslint-disable-next-line import/no-unresolved
import express4 from "express4";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
    createExpressAuthKit,
    tenantFromParam,
    type ExpressAuthKit,
} from "../src";

const TENANT = "22222222-2222-4222-8222-222222222222";
const PRINCIPAL = "11111111-1111-4111-8111-111111111111";
const AUTH_USER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

interface Stub {
    /** null means "this token maps to no authz identity". */
    principal?: string | null;
    scopes?: string[];
    verify?: string | null;
}

function build(app: Express, stub: Stub) {
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

    const auth: ExpressAuthKit = createExpressAuthKit({
        query,
        verifyBearer: async () => (stub.verify === undefined ? AUTH_USER : stub.verify),
        resolveTenant: tenantFromParam("tenantId"),
    });

    const handler = vi.fn((_req: unknown, res: { json: (b: unknown) => void }) => {
        res.json({ ok: true });
    });

    return { auth, query, handler, app, audited };
}

for (const [label, factory] of [
    ["express 5", express5],
    ["express 4", express4],
] as const) {
    describe(`guards on ${label}`, () => {
        let app: Express;

        beforeEach(() => {
            app = (factory as typeof express5)();
        });

        it("allows a principal holding the scope", async () => {
            const { auth, handler } = build(app, {
                principal: PRINCIPAL,
                scopes: ["authz.roles.read"],
            });

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(200);

            expect(handler).toHaveBeenCalledOnce();
        });

        it("returns 403 and never runs the handler when the scope is absent", async () => {
            const { auth, handler } = build(app, {
                principal: PRINCIPAL,
                scopes: ["something.else"],
            });

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(403);

            expect(res.body.error).toBe("forbidden");
            expect(handler).not.toHaveBeenCalled();
        });

        it("returns 401 when no credential was presented", async () => {
            const { auth, handler } = build(app, { principal: PRINCIPAL });

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app).get(`/t/${TENANT}/x`).expect(401);

            expect(res.body.error).toBe("unauthenticated");
            expect(handler).not.toHaveBeenCalled();
        });

        /**
         * Open question 1 at the HTTP layer: a token that verified against the project's own JWKS
         * but maps to no authz identity. Must be a clean 403 -- not a 500, and not a pass.
         */
        it("returns 403, not 500, for a verified token with no authz identity", async () => {
            const { auth, handler } = build(app, {
                principal: null,
                verify: AUTH_USER,
            });

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(403);

            expect(res.body.error).toBe("forbidden");
            expect(handler).not.toHaveBeenCalled();
        });

        it("returns 400 for an unresolvable tenant, without querying", async () => {
            const { auth, handler, query } = build(app, {
                principal: PRINCIPAL,
                scopes: ["authz.roles.read"],
            });

            app.use(auth.authenticate());
            // Route param is not a uuid, so the resolver yields nothing.
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app)
                .get("/t/not-a-uuid/x")
                .set("authorization", "Bearer tok")
                .expect(400);

            expect(res.body.error).toBe("tenant_required");
            expect(handler).not.toHaveBeenCalled();
            expect(
                query.mock.calls.filter(c => String(c[0]).includes("effective_scopes")),
            ).toHaveLength(0);
        });

        // A wiring bug must not be indistinguishable from an allow.
        it("returns a 500-class error when authenticate() was never mounted", async () => {
            const { auth, handler } = build(app, { principal: PRINCIPAL });

            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(500);

            expect(res.body.error).toBe("middleware_missing");
            expect(handler).not.toHaveBeenCalled();
        });

        /**
         * The v4 case specifically: v4's router does not await handlers, so without the wrapper a
         * rejection would hang the request rather than produce a status.
         */
        it("routes a rejected query to the error handler instead of hanging", async () => {
            const auth = createExpressAuthKit({
                query: async () => {
                    throw new Error("connection reset");
                },
                verifyBearer: async () => AUTH_USER,
                resolveTenant: tenantFromParam("tenantId"),
            });

            const handler = vi.fn();

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireScope("authz.roles.read"),
                handler as never,
            );
            app.use(((err: Error, _q: unknown, res: never, _n: unknown) => {
                (res as unknown as { status: (n: number) => { json: (b: unknown) => void } })
                    .status(599)
                    .json({ message: err.message });
            }) as never);

            const res = await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(599);

            expect(res.body.message).toBe("connection reset");
            expect(handler).not.toHaveBeenCalled();
        });

        it("makes one effective_scopes round trip for several scope checks", async () => {
            const { auth, query, handler } = build(app, {
                principal: PRINCIPAL,
                scopes: ["a", "b", "c"],
            });

            app.use(auth.authenticate());
            app.get(
                "/t/:tenantId/x",
                auth.requireAllScopes(["a", "b", "c"]),
                handler as never,
            );
            app.use(auth.errorHandler());

            await request(app)
                .get(`/t/${TENANT}/x`)
                .set("authorization", "Bearer tok")
                .expect(200);

            expect(
                query.mock.calls.filter(c => String(c[0]).includes("effective_scopes")),
            ).toHaveLength(1);
        });

        it("binds the request's principal to the write API, and null when there is none", async () => {
            const { auth } = build(app, { principal: PRINCIPAL, scopes: [] });
            const seen: Array<string | null> = [];

            app.use(auth.authenticate());
            app.get("/probe", ((req: never, res: never) => {
                const ctx = (req as unknown as { authKit: { as: unknown } }).authKit;
                seen.push(ctx.as === null ? null : "bound");
                (res as unknown as { json: (b: unknown) => void }).json({});
            }) as never);

            await request(app).get("/probe").set("authorization", "Bearer tok");
            await request(app).get("/probe");

            expect(seen).toEqual(["bound", null]);
        });

        /**
         * The route requireIdentity exists for: `create_workspace` requires no scope at any
         * tenant, and a POST /workspaces request names none, so requireScope cannot guard it --
         * the last case here is the proof, and the reason this is not just a faster guard.
         */
        it("requireIdentity allows any principal, without an effective_scopes round trip", async () => {
            const { auth, handler, query } = build(app, {
                principal: PRINCIPAL,
                scopes: [],
            });

            app.use(auth.authenticate());
            app.post("/workspaces", auth.requireIdentity(), handler as never);
            app.use(auth.errorHandler());

            await request(app)
                .post("/workspaces")
                .set("authorization", "Bearer tok")
                .expect(200);

            expect(handler).toHaveBeenCalledOnce();
            // Holding no scope at all is fine here: SQL decides, and needs no tenant to do it.
            expect(
                query.mock.calls.filter(c => String(c[0]).includes("effective_scopes")),
            ).toHaveLength(0);
        });

        it("requireIdentity returns 401 when no credential was presented", async () => {
            const { auth, handler, audited } = build(app, { principal: PRINCIPAL });

            app.use(auth.authenticate());
            app.post("/workspaces", auth.requireIdentity(), handler as never);
            app.use(auth.errorHandler());

            const res = await request(app).post("/workspaces").expect(401);

            expect(res.body.error).toBe("unauthenticated");
            expect(handler).not.toHaveBeenCalled();
            expect(audited).toHaveLength(0);
        });

        it("requireIdentity returns 403, not 500, for a token with no authz identity", async () => {
            const { auth, handler, audited } = build(app, {
                principal: null,
                verify: AUTH_USER,
            });

            app.use(auth.authenticate());
            app.post("/workspaces", auth.requireIdentity(), handler as never);
            app.use(auth.errorHandler());

            const res = await request(app)
                .post("/workspaces")
                .set("authorization", "Bearer tok")
                .expect(403);

            expect(res.body.error).toBe("forbidden");
            expect(handler).not.toHaveBeenCalled();
            // Recorded with no tenant, exactly as enforceGuard's own second branch records it.
            expect(audited).toHaveLength(1);
            expect(audited[0]).toEqual(expect.arrayContaining(["authenticate", "request"]));
        });

        // A wiring bug must not be indistinguishable from an allow here either.
        it("requireIdentity is a 500 when authenticate() was never mounted", async () => {
            const { auth, handler } = build(app, { principal: PRINCIPAL });

            app.post("/workspaces", auth.requireIdentity(), handler as never);
            app.use(auth.errorHandler());

            const res = await request(app)
                .post("/workspaces")
                .set("authorization", "Bearer tok")
                .expect(500);

            expect(res.body.error).toBe("middleware_missing");
            expect(handler).not.toHaveBeenCalled();
        });

        it("guards a route requireScope cannot: no tenant to resolve", async () => {
            const { auth, handler } = build(app, {
                principal: PRINCIPAL,
                scopes: ["authz.tenants.write"],
            });

            app.use(auth.authenticate());
            app.post(
                "/scoped-workspaces",
                auth.requireScope("authz.tenants.write"),
                handler as never,
            );
            app.use(auth.errorHandler());

            const res = await request(app)
                .post("/scoped-workspaces")
                .set("authorization", "Bearer tok")
                .expect(400);

            expect(res.body.error).toBe("tenant_required");
            expect(handler).not.toHaveBeenCalled();
        });
    });
}

describe("audit context on Express", () => {
    let app: Express;

    beforeEach(() => {
        app = express5();
    });

    it("records a refused request with the context Express can give", async () => {
        const { auth, handler, audited } = build(app, {
            principal: PRINCIPAL,
            scopes: [],
        });

        app.use(auth.authenticate());
        app.post("/t/:tenantId/x", auth.requireScope("authz.roles.read"), handler as never);

        await request(app)
            .post(`/t/${TENANT}/x`)
            .set("authorization", "Bearer tok")
            .set("x-request-id", "req-42")
            .set("user-agent", "vitest");

        expect(handler).not.toHaveBeenCalled();
        expect(audited).toHaveLength(1);

        const context = audited[0]?.at(-1) as Record<string, string>;

        expect(context).toMatchObject({
            request_id: "req-42",
            method: "POST",
            user_agent: "vitest",
            // The URL, not the pattern: req.route is not populated until Express has matched a
            // route, and authenticate() runs before that.
            route: `/t/${TENANT}/x`,
        });
    });

    it("mints a request id when nothing carries one", async () => {
        const { auth, audited } = build(app, { principal: PRINCIPAL, scopes: [] });

        app.use(auth.authenticate());
        app.get("/t/:tenantId/x", auth.requireScope("authz.roles.read"), (() => {}) as never);

        await request(app).get(`/t/${TENANT}/x`).set("authorization", "Bearer tok");

        const context = audited[0]?.at(-1) as Record<string, string>;

        // Still correlates this request's rows with each other, which is most of the value.
        expect(context["request_id"]).toMatch(/^[0-9a-f-]{36}$/);
    });

    it("honours a caller-supplied request context, including none at all", async () => {
        const audited: unknown[][] = [];

        const query = vi.fn(async (sql: string, params: readonly unknown[]) => {
            if (sql.includes("principal_for_auth_user")) return [{ result: PRINCIPAL }];
            if (sql.includes("effective_scopes")) return [];

            if (sql.includes("log_audit")) {
                audited.push([...params]);

                return [{ result: "audit-row" }];
            }

            throw new Error(`unexpected sql: ${sql}`);
        });

        const auth = createExpressAuthKit({
            query,
            verifyBearer: async () => AUTH_USER,
            resolveTenant: tenantFromParam("tenantId"),
            // An app that does not want request metadata in its audit rows -- a jurisdiction
            // where the IP is personal data, say -- opts out here rather than losing the row.
            requestContext: () => null,
        });

        app.use(auth.authenticate());
        app.get("/t/:tenantId/x", auth.requireScope("authz.roles.read"), (() => {}) as never);

        await request(app).get(`/t/${TENANT}/x`).set("authorization", "Bearer tok");

        // The denial is still recorded; it just says nothing about the request.
        expect(audited).toHaveLength(1);
        expect(audited[0]?.at(-1)).toBeNull();
    });
});

describe("async wrapper shape", () => {
    // The assertion that actually pins Express 4 compatibility: the handler must be sync-outer,
    // so v5's router has nothing to await and there is exactly one path to next(err).
    it("returns undefined rather than a promise", () => {
        const auth = createExpressAuthKit({
            query: async () => [],
            verifyBearer: async () => null,
            resolveTenant: () => TENANT,
        });

        const returned = auth.authenticate()(
            { headers: {} } as never,
            {} as never,
            () => {},
        );

        expect(returned).toBeUndefined();
    });
});
