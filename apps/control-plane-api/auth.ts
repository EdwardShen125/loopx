/** Auth middleware for the control plane API (Phase 2).
 *
 * Modes:
 *  - "none": dev only, no auth
 *  - "api_key": Bearer token + X-Tenant-ID header
 */
import type {Context, Next} from "hono";
import {timingSafeEqual} from "node:crypto";

export interface AuthConfig {
  mode: "none" | "api_key";
  apiKey: string;
}

const PUBLIC_PATHS = new Set(["/", "/healthz", "/readyz"]);

export function authMiddleware(config: AuthConfig) {
  return async (c: Context, next: Next) => {
    const path = new URL(c.req.url).pathname;
    if (PUBLIC_PATHS.has(path)) return next();

    if (config.mode === "none") {
      c.set("tenantId" as never, c.req.header("X-Tenant-ID") ?? "00000000-0000-0000-0000-000000000000");
      return next();
    }

    // api_key mode
    const auth = c.req.header("Authorization") ?? "";
    if (!auth.startsWith("Bearer ")) {
      return c.json({detail: "missing or invalid Authorization header"}, 401);
    }
    const token = auth.slice(7).trim();
    const a = Buffer.from(token);
    const b = Buffer.from(config.apiKey);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return c.json({detail: "invalid credentials"}, 401);
    }

    const tenantId = c.req.header("X-Tenant-ID");
    if (!tenantId) {
      return c.json({detail: "missing X-Tenant-ID header"}, 401);
    }
    c.set("tenantId" as never, tenantId);
    return next();
  };
}

export function getTenantId(c: Context): string {
  return (c as any).get("tenantId") ?? "00000000-0000-0000-0000-000000000000";
}
