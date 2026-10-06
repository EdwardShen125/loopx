/** LoopX Control Plane API — TypeScript native, aligned with upstream coordination layer.
 *
 * Replaces the Python loopx-control with a TS service that imports
 * PostgreSqlAuthorityStore/Service and task_lease directly from the fork.
 *
 * Phase 1: Receipt ingestion (persistent idempotency via AuthorityStore commits)
 * Phase 2: API key auth middleware
 * Phase 3: Todo lease acquire/lifecycle via canonical task lease
 */
import {Hono} from "hono";
import {serve} from "@hono/node-server";
import {Pool, type PoolClient} from "pg";
import {timingSafeEqual} from "node:crypto";

import {
  PostgreSqlAuthorityStore,
  installPostgreSqlAuthorityStoreSchema,
  type PostgreSqlAuthorityConnection,
  type PostgreSqlAuthorityDatabase,
} from "../../loopx/control_plane/coordination/postgresql_authority_store.ts";
import {
  PostgreSqlAuthorityService,
} from "../../loopx/control_plane/coordination/postgresql_authority_service.ts";
import {
  executeCanonicalTaskLeaseAcquire,
} from "../../loopx/control_plane/coordination/task_lease_acquire.ts";
import {
  coordinationTodoReadModel,
  TODO_CANONICAL_READ_RECORD_SCHEMA,
} from "../../loopx/control_plane/coordination/coordination_projection.ts";
import { canonicalAuthoritySha256 } from "../../loopx/control_plane/coordination/authority_store_codec.ts";

// ─── Configuration ────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "18082", 10);
const DATABASE_URL = process.env.LOOPX_DATABASE_URL ??
  "postgresql://loopx:loopx_dev_password@localhost:5433/loopx";
const AUTH_MODE = (process.env.LOOPX_AUTH_MODE ?? "none") as "none" | "api_key";
const API_KEY = process.env.LOOPX_API_KEY ?? "dev-loopx-key";
const STORE_IDENTITY = process.env.LOOPX_STORE_IDENTITY ??
  `postgresql:${"0".repeat(32)}`;

// ─── Database ─────────────────────────────────────────────────────────────────

const pool = new Pool({connectionString: DATABASE_URL, max: 10});

function databaseFromPool(value: Pool): PostgreSqlAuthorityDatabase {
  return {
    connect: async () => {
      const client: PoolClient = await value.connect();
      const connection: PostgreSqlAuthorityConnection = {
        query: async (text, values) =>
          await client.query(text, values ? [...values] : undefined),
        release: (error) => client.release(error),
      };
      return connection;
    },
  };
}

const database = databaseFromPool(pool);

// Install schema on startup
await installPostgreSqlAuthorityStoreSchema(database, STORE_IDENTITY);

// ─── Auth ─────────────────────────────────────────────────────────────────────

type Env = {
  Variables: {
    tenantId: string;
  };
};

const app = new Hono<Env>();

// Auth middleware
const PUBLIC_PATHS = new Set(["/", "/healthz", "/readyz"]);

app.use("*", async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (PUBLIC_PATHS.has(path)) return next();

  if (AUTH_MODE === "none") {
    c.set("tenantId", c.req.header("X-Tenant-ID") ?? "00000000-0000-0000-0000-000000000000");
    return next();
  }

  const auth = c.req.header("Authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return c.json({detail: "missing or invalid Authorization header"}, 401);
  }
  const token = auth.slice(7).trim();
  const a = Buffer.from(token);
  const b = Buffer.from(API_KEY);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return c.json({detail: "invalid credentials"}, 401);
  }

  const tenantId = c.req.header("X-Tenant-ID");
  if (!tenantId) {
    return c.json({detail: "missing X-Tenant-ID header"}, 401);
  }
  c.set("tenantId", tenantId);
  return next();
});

// ─── Health ───────────────────────────────────────────────────────────────────

app.get("/healthz", (c) => c.json({status: "ok"}));

app.get("/readyz", async (c) => {
  try {
    await pool.query("SELECT 1");
    return c.json({status: "ready", event_store: "connected"});
  } catch {
    return c.json({status: "degraded", event_store: "disconnected"}, 503);
  }
});

app.get("/", (c) => c.json({
  service: "loopx-control-plane-api",
  status: "ok",
  version: "0.1.0",
  auth_mode: AUTH_MODE,
}));

// ─── Receipt ingestion (Phase 1: AuthorityStore-backed idempotency) ──────────

interface PlatformAnalysisReceipt {
  schema_version: string;
  tenant_id: string;
  project_id: string;
  goal_id: string;
  stage_id: string;
  stage_revision: number;
  repair_epoch: number;
  depth_tier: string;
  todo_id: string;
  work_unit_id: string;
  result_commit_id: string;
  attempt_id: string;
  source_commit_sha: string;
  merged_commit_sha: string;
  manifest_sha256: string;
  record_ids: string[];
  record_revision_ids: string[];
  artifact_manifest_sha256?: string;
  mechanical_gate_receipt_id?: string;
  status: string;
  coverage?: Record<string, number>;
  counts?: Record<string, number>;
  next_action?: {type: string; target_stage_id?: string; reason?: string};
  idempotency_key: string;
  created_at: string;
}

app.post("/v1/receipts/platform", async (c) => {
  let body: PlatformAnalysisReceipt;
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  if (body.schema_version !== "platform_analysis_receipt_v1") {
    return c.json({detail: `unsupported schema_version: ${body.schema_version}`}, 422);
  }

  const key = c.req.header("X-Idempotency-Key") ?? body.idempotency_key;
  if (!key) {
    return c.json({detail: "missing idempotency_key"}, 422);
  }

  const tenantId = c.get("tenantId");

  // Check for existing receipt via AuthorityStore readReceipt (idempotent replay).
  const store = new PostgreSqlAuthorityStore(database, {
    tenant_id: tenantId,
    goal_id: body.goal_id,
  });

  // Try to read existing receipt by operation_id (idempotency).
  const operationId = `receipt:${key}`;
  const existing = await store.readReceipt(operationId);
  if (existing.status === "found") {
    const receipts = existing.receipts as Array<{receipt_id?: string}>;
    const prior = receipts[0];
    return c.json({
      status: "duplicate",
      receipt_id: prior?.receipt_id ?? operationId,
      idempotency_key: key,
    });
  }

  // New receipt: commit to the AuthorityStore (atomic event + projection + receipt).
  const receiptId = `rcpt-${crypto.randomUUID().slice(0, 16)}`;

  // Load current head to get expected_provider_revision for CAS.
  const head = await store.loadAuthority();
  const expectedRevision = head.status === "loaded" ? head.provider_revision : null;
  const currentHead = head.status === "loaded" ? head.head : null;

  // Build next projection (append receipt to head state).
  const priorReceipts = Array.isArray((currentHead as any)?.receipts)
    ? (currentHead as any).receipts : [];
  const nextProjection = {
    ...(currentHead as Record<string, unknown> ?? {}),
    receipts: [...priorReceipts, {
      receipt_id: receiptId,
      status: "accepted",
      idempotency_key: key,
      todo_id: body.todo_id,
      work_unit_id: body.work_unit_id,
      merged_commit_sha: body.merged_commit_sha,
    }],
  };

  const commitResult = await store.commitAuthority({
    expected_provider_revision: expectedRevision,
    operation_id: operationId,
    events: [{
      type: "PlatformAnalysisReceiptReceived",
      payload: body as unknown as Record<string, unknown>,
    }],
    next_projection: nextProjection,
    receipts: [{
      operation_id: operationId,
      receipt_id: receiptId,
      status: "accepted",
      idempotency_key: key,
    }],
  });

  if (commitResult.status === "applied") {
    return c.json({
      status: "accepted",
      receipt_id: receiptId,
      idempotency_key: key,
    });
  }

  // Applied or conflict — treat as duplicate if receipt exists.
  const recheck = await store.readReceipt(operationId);
  if (recheck.status === "found") {
    const rcpts = recheck.receipts as Array<{receipt_id?: string}>;
    const prior = rcpts[0];
    return c.json({
      status: "duplicate",
      receipt_id: prior?.receipt_id ?? operationId,
      idempotency_key: key,
    });
  }

  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// ─── Todo management (create todos in a Goal head) ─────────────────────────

app.post("/v1/goals/:goalId/todos", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  interface TodoItem {
    todo_id: string;
    text: string;
    role?: string;
    status?: string;
    task_class?: string;
  }
  let body: {todos: TodoItem[]};
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  const store = new PostgreSqlAuthorityStore(database, {
    tenant_id: tenantId,
    goal_id: goalId,
  });

  // Load current head or create initial projection.
  const head = await store.loadAuthority();
  const expectedRevision = head.status === "loaded" ? head.provider_revision : null;
  const currentHead = head.status === "loaded" ? head.head : null;
  const existingTodos = Array.isArray((currentHead as any)?.todos)
    ? [...(currentHead as any).todos] : [];

  // Append new todos with todo_item_v0 schema.
  const newTodos = body.todos.map((t, i) => ({
    schema_version: "todo_item_v0",
    todo_id: t.todo_id,
    index: existingTodos.length + i,
    done: false,
    text: t.text,
    role: t.role ?? "agent",
    status: t.status ?? "open",
    priority: null,
    title: null,
    archive_state: "active",
    source_section: "Agent Todo",
    task_class: t.task_class ?? "advancement_task",
    action_kind: null,
    task_domain: null,
    capability_binding_ref: null,
    task_repository: null,
    continuation_policy: null,
    removed_continuation_policy: null,
    claimed_by: null,
    excluded_agents: [],
  }));

  const allTodos = [...existingTodos, ...newTodos];
  // Sort by todo_id (deterministic order required by projection validation).
  allTodos.sort((a, b) => a.todo_id.localeCompare(b.todo_id));
  const readModel = coordinationTodoReadModel(
    allTodos as unknown as Array<Record<string, unknown>>,
    TODO_CANONICAL_READ_RECORD_SCHEMA,
  );
  const nextProjection = {
    ...(currentHead as Record<string, unknown> ?? {}),
    goal_id: goalId,
    todos: allTodos,
    leases: [],
    todo_read_model: readModel,
  };

  const operationId = `todo-create:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  const commitResult = await store.commitAuthority({
    expected_provider_revision: expectedRevision,
    operation_id: operationId,
    events: newTodos.map(t => ({
      type: "TodoCreated",
      payload: t as unknown as Record<string, unknown>,
    })),
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({status: "created", todo_count: nextProjection.todos.length}, 201);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// ─── Todo Lease operations (Phase 3: canonical task lease) ───────────────────

app.post("/v1/todos/:todoId/lease/acquire", async (c) => {
  const tenantId = c.get("tenantId");
  const todoId = c.req.param("todoId");

  let body: {
    goal_id: string;
    owner: string;
    idempotency_key: string;
    expected_version?: number;
    ttl_seconds?: number;
    write_scopes?: string[];
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  const store = new PostgreSqlAuthorityStore(database, {
    tenant_id: tenantId,
    goal_id: body.goal_id,
  });

  const result = await executeCanonicalTaskLeaseAcquire(store, {
    goal_id: body.goal_id,
    todo_id: todoId,
    owner: body.owner,
    idempotency_key: body.idempotency_key,
    expected_version: body.expected_version ?? null,
    ttl_seconds: body.ttl_seconds ?? null,
    write_scopes: body.write_scopes ?? ["todo"],
    registered_agents: [body.owner],
    now: new Date(),
  });

  const status = result.status === "failed" ? 409 : 200;
  return c.json(result, status);
});

// ─── Start ────────────────────────────────────────────────────────────────────

const server = serve({fetch: app.fetch, port: PORT}, (info) => {
  console.log(`loopx-control-plane-api listening on http://localhost:${info.port}`);
  console.log(`  auth_mode: ${AUTH_MODE}`);
  console.log(`  database: ${DATABASE_URL.replace(/:[^:]*@/, ":***@")}`);
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  server.close();
  await pool.end();
  process.exit(0);
});
process.on("SIGINT", async () => {
  server.close();
  await pool.end();
  process.exit(0);
});
