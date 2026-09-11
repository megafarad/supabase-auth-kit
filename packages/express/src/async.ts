import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * Wraps an async handler so a rejection always reaches `next`.
 *
 * Express 5 awaits a handler's return value and forwards a rejection itself; Express 4 does not.
 * On v4 an unhandled rejection means the request **hangs** until a timeout, and on modern Node the
 * default `unhandledRejection` behaviour can take the process down -- so this is an availability
 * bug there, not merely a wrong status code. The peer range admits both, so the package never
 * relies on the framework for it.
 *
 * Two details are load-bearing:
 *
 * The returned function is **synchronous**. An `async` outer would itself return a promise that
 * Express 5's router also awaits, creating two routes to `next(err)` and making the two versions
 * behave differently. Sync outer plus `.catch` is one path, identical on both.
 *
 * `next` is latched. If the inner handler calls `next()` and then throws, the catch would call
 * `next(err)` a second time, after a response may already be in flight.
 */
export function wrapAsync(
    handler: (
        req: Request,
        res: Response,
        next: NextFunction,
    ) => Promise<void>,
): RequestHandler {
    return (req, res, next) => {
        let called = false;

        const once: NextFunction = (...args: unknown[]) => {
            if (called) {
                return;
            }

            called = true;

            (next as (...a: unknown[]) => void)(...args);
        };

        void handler(req, res, once).catch(once);
    };
}
