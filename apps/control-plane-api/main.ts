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
import {
  findDownstream,
  checkReadiness,
  buildBackfillMutations,
  type TodoDependencyEdge,
} from "./dependency.ts";
import {
  compileTodoBundle,
  convertGateReceipt,
  type GoalSpec,
  type PlatformAnalysisReceiptInput,
} from "./capability.ts";

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
    // Auto-gate: process the receipt as a Gate transition (Phase 5).
    let gateResult: {transition: string; from?: string; to?: string} | null = null;
    try {
      gateResult = await processGateTransition(tenantId, body.goal_id, body);
    } catch (gateErr) {
      console.warn("auto-gate failed (non-blocking):", gateErr);
    }

    return c.json({
      status: "accepted",
      receipt_id: receiptId,
      idempotency_key: key,
      gate: gateResult,
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

// ─── Phase 4: Todo Dependency DAG + Backfill ────────────────────────────────

// Add a dependency edge between two todos.
app.post("/v1/goals/:goalId/dependencies", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  interface DepEdge {
    upstream_todo_id: string;
    downstream_todo_id: string;
    dependency_type: string;
    upstream_commit_sha?: string;
    gate_id?: string;
  }
  let body: {dependencies: DepEdge[]};
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal head not found; create todos first"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const existingDeps = Array.isArray(currentHead.todo_dependencies)
    ? [...currentHead.todo_dependencies] as TodoDependencyEdge[] : [];
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos as Array<{todo_id: string}> : [];

  // Validate all referenced todos exist.
  const todoIds = new Set(todos.map(t => t.todo_id));
  for (const dep of body.dependencies) {
    if (!todoIds.has(dep.upstream_todo_id)) {
      return c.json({detail: `upstream todo not found: ${dep.upstream_todo_id}`}, 404);
    }
    if (!todoIds.has(dep.downstream_todo_id)) {
      return c.json({detail: `downstream todo not found: ${dep.downstream_todo_id}`}, 404);
    }
    if (!["hard_completion", "gate_acceptance", "source_commit_current"].includes(dep.dependency_type)) {
      return c.json({detail: `invalid dependency_type: ${dep.dependency_type}`}, 422);
    }
  }

  const newEdges: TodoDependencyEdge[] = body.dependencies.map(d => ({
    upstream_todo_id: d.upstream_todo_id,
    downstream_todo_id: d.downstream_todo_id,
    dependency_type: d.dependency_type as TodoDependencyEdge["dependency_type"],
    upstream_commit_sha: d.upstream_commit_sha ?? null,
    gate_id: d.gate_id ?? null,
  }));

  const allDeps = [...existingDeps, ...newEdges];
  const nextProjection = {...currentHead, todo_dependencies: allDeps};
  const operationId = `dep-add:${Date.now()}:${Math.random().toString(36).slice(2)}`;

  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: newEdges.map(e => ({type: "DependencyAdded", payload: e as unknown as Record<string, unknown>})),
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({status: "created", dependency_count: allDeps.length}, 201);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// Check if a todo is ready to execute.
app.get("/v1/goals/:goalId/todos/:todoId/readiness", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");
  const todoId = c.req.param("todoId");

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos as Array<{todo_id: string; status: string}> : [];
  const deps = Array.isArray(currentHead.todo_dependencies) ? currentHead.todo_dependencies as TodoDependencyEdge[] : [];

  const readiness = checkReadiness(todoId, todos, deps);

  // Human Gate check: if a dependency has a gate_id, verify it's approved.
  const gates = Array.isArray(currentHead.human_gates)
    ? currentHead.human_gates as Array<{gate_id: string; approved: boolean}>
    : [];
  const gateLookup = new Map(gates.map(g => [g.gate_id, g]));
  for (const dep of deps) {
    if (dep.downstream_todo_id !== todoId || !dep.gate_id) continue;
    const gate = gateLookup.get(dep.gate_id);
    if (!gate || !gate.approved) {
      readiness.blocked_by.push({
        todo_id: dep.upstream_todo_id,
        status: `gate_pending:${dep.gate_id}`,
        type: dep.dependency_type,
      });
    }
  }
  readiness.ready = readiness.blocked_by.length === 0;

  return c.json({todo_id: todoId, ...readiness});
});

// Trigger Backfill: mark downstream todos as provisional/paused/reopened.
app.post("/v1/goals/:goalId/backfill", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  interface BackfillRequest {
    upstream_todo_id: string;
    new_commit_sha: string;
    reason?: string;
  }
  let body: BackfillRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos)
    ? currentHead.todos as Array<{todo_id: string; status: string; claimed_by: string | null} & Record<string, unknown>>
    : [];
  const deps = Array.isArray(currentHead.todo_dependencies) ? currentHead.todo_dependencies as TodoDependencyEdge[] : [];

  // Build mutations for all downstream todos.
  const todoData = todos.map(t => ({
    todo_id: t.todo_id,
    status: t.status,
    claimed_by: t.claimed_by,
    todo: t as Record<string, unknown>,
  }));
  const mutations = buildBackfillMutations(deps, body.upstream_todo_id, todoData);

  if (mutations.length === 0) {
    return c.json({status: "no_downstream", affected: 0});
  }

  // Build next projection with backfill status changes.
  const mutationMap = new Map(mutations.map(m => [m.todo_id, m]));
  const updatedTodos = todos.map(t => {
    const m = mutationMap.get(t.todo_id);
    if (!m) return t;
    return {...t, status: m.new_status, backfill_marker: `backfill-from:${body.upstream_todo_id}`};
  });

  // Rebuild read model.
  const sortedTodos = [...updatedTodos].sort((a, b) => a.todo_id.localeCompare(b.todo_id));
  const readModel = coordinationTodoReadModel(
    sortedTodos as unknown as Array<Record<string, unknown>>,
    TODO_CANONICAL_READ_RECORD_SCHEMA,
  );
  const nextProjection = {
    ...currentHead,
    todos: sortedTodos,
    todo_read_model: readModel,
  };

  const operationId = `backfill:${body.upstream_todo_id}:${Date.now()}`;
  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: [{
      type: "BackfillPropagated",
      payload: {
        upstream_todo_id: body.upstream_todo_id,
        new_commit_sha: body.new_commit_sha,
        reason: body.reason ?? "backfill",
        affected: mutations.map(m => ({todo_id: m.todo_id, old: m.old_status, new: m.new_status})),
      } as unknown as Record<string, unknown>,
    }],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({
      status: "propagated",
      upstream_todo_id: body.upstream_todo_id,
      affected: mutations.map(m => ({todo_id: m.todo_id, old_status: m.old_status, new_status: m.new_status})),
    });
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// ─── Phase 5: Reverse Analysis Capability ─────────────────────────────────────

// Compile a GoalSpec into an L0-L7/A-B-C Todo bundle with dependencies.
app.post("/v1/goals/:goalId/compile", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  let spec: GoalSpec;
  try {
    spec = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }
  if (!spec.sample_name || !spec.depth_tier || !spec.stages?.length) {
    return c.json({detail: "sample_name, depth_tier, and stages are required"}, 422);
  }

  const compiled = compileTodoBundle(spec);

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  const expectedRevision = head.status === "loaded" ? head.provider_revision : null;
  const currentHead = head.status === "loaded" ? head.head as Record<string, unknown> : {};

  // Merge with existing todos.
  const existingTodos = Array.isArray(currentHead.todos) ? [...currentHead.todos] as Array<{todo_id: string}> : [];
  const existingIds = new Set(existingTodos.map(t => t.todo_id));
  const newTodos = compiled.todos.filter(t => !existingIds.has(t.todo_id));
  const allTodos = [...existingTodos, ...newTodos.map(t => ({
    schema_version: "todo_item_v0",
    ...t,
    priority: null,
    title: null,
    action_kind: null,
    task_domain: null,
    capability_binding_ref: null,
    task_repository: null,
    continuation_policy: null,
    removed_continuation_policy: null,
    excluded_agents: [],
  }))];
  allTodos.sort((a, b) => a.todo_id.localeCompare(b.todo_id));

  const readModel = coordinationTodoReadModel(
    allTodos as unknown as Array<Record<string, unknown>>,
    TODO_CANONICAL_READ_RECORD_SCHEMA,
  );

  // Merge with existing dependencies.
  const existingDeps = Array.isArray(currentHead.todo_dependencies) ? [...currentHead.todo_dependencies] as TodoDependencyEdge[] : [];
  const depKeys = new Set(existingDeps.map(d => `${d.upstream_todo_id}->${d.downstream_todo_id}`));
  const newDeps = compiled.dependencies.filter(d => !depKeys.has(`${d.upstream_todo_id}->${d.downstream_todo_id}`));
  const allDeps = [...existingDeps, ...newDeps];

  const nextProjection = {
    ...currentHead,
    goal_id: goalId,
    todos: allTodos,
    leases: Array.isArray(currentHead.leases) ? currentHead.leases : [],
    todo_dependencies: allDeps,
    todo_read_model: readModel,
  };

  const operationId = `compile:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  const commitResult = await store.commitAuthority({
    expected_provider_revision: expectedRevision,
    operation_id: operationId,
    events: [
      ...newTodos.map(t => ({type: "TodoCompiled", payload: {todo_id: t.todo_id, stage_id: t.stage_id, depth_tier: t.depth_tier}})),
      ...newDeps.map(d => ({type: "DependencyCompiled", payload: d as unknown as Record<string, unknown>})),
    ],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({
      status: "compiled",
      goal_id: goalId,
      todos_created: newTodos.length,
      dependencies_created: newDeps.length,
      total_todos: allTodos.length,
      total_dependencies: allDeps.length,
      stages: spec.stages,
    }, 201);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// Process a Gate Receipt: convert PlatformAnalysisReceipt to LoopX Gate transition.
app.post("/v1/goals/:goalId/gate", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  let receipt: PlatformAnalysisReceiptInput;
  try {
    receipt = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }

  // Determine stage sequence from the head's todo stage_ids.
  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos as Array<{todo_id: string; stage_id?: string}> : [];
  const stages = [...new Set(todos.map(t => t.stage_id).filter(Boolean))] as string[];

  if (stages.length === 0) {
    return c.json({detail: "no stages found in goal"}, 422);
  }

  const transition = convertGateReceipt(receipt, stages);

  // Apply gate transition: update the source todo status + open gate.
  const gateId = "gate_id" in transition ? transition.gate_id : null;
  let updatedTodos = todos;
  let eventPayload: Record<string, unknown> = {transition, receipt_idempotency_key: receipt.idempotency_key};

  if (transition.action === "advance_stage") {
    updatedTodos = todos.map(t =>
      t.stage_id === transition.from_stage ? {...t, status: "done", done: true} : t
    );
  } else if (transition.action === "block") {
    updatedTodos = todos.map(t =>
      t.stage_id === transition.stage ? {...t, status: "blocked"} : t
    );
  } else if (transition.action === "complete_goal") {
    updatedTodos = todos.map(t => ({...t, status: "done", done: true}));
  }

  if (transition.action !== "no_change") {
    const sortedTodos = [...updatedTodos].sort((a, b) => a.todo_id.localeCompare(b.todo_id));
    const readModel = coordinationTodoReadModel(
      sortedTodos as unknown as Array<Record<string, unknown>>,
      TODO_CANONICAL_READ_RECORD_SCHEMA,
    );
    const nextProjection = {...currentHead, todos: sortedTodos, todo_read_model: readModel};
    const operationId = `gate:${receipt.idempotency_key}`;

    // Idempotency: check for existing receipt with same operation.
    const existing = await store.readReceipt(operationId);
    if (existing.status === "found") {
      return c.json({status: "duplicate", transition}, 200);
    }

    const commitResult = await store.commitAuthority({
      expected_provider_revision: head.provider_revision,
      operation_id: operationId,
      events: [{type: `GateTransition:${transition.action}`, payload: eventPayload}],
      next_projection: nextProjection,
      receipts: [{operation_id: operationId, status: "applied", transition: transition.action}],
    });

    if (commitResult.status !== "applied") {
      return c.json({detail: "gate commit failed", reason: commitResult.status}, 500);
    }
  }

  return c.json({status: "processed", transition, gate_id: gateId, stages});
});

// ─── Goal state read (for frontend visualization) ──────────────────────────

app.get("/v1/goals/:goalId", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos : [];
  const deps = Array.isArray(currentHead.todo_dependencies) ? currentHead.todo_dependencies : [];

  return c.json({
    goal_id: goalId,
    provider_revision: head.provider_revision,
    cursor: head.cursor,
    todos: todos,
    dependencies: deps,
  });
});

// ─── TodoActivation async flow (design §12.3) ────────────────────────────────

interface TodoActivationRequest {
  activation_id: string;
  idempotency_key: string;
  tenant_id: string;
  project_id: string;
  goal_id: string;
  todo_id: string;
  todo_aggregate_version: number;
  loopx_event_id?: string;
  source_commit_sha: string;
  manifest_sha256: string;
  work_unit_specs?: Array<Record<string, unknown>>;
  required_capabilities?: string[];
  priority?: number;
  platform_resource_budget?: Record<string, unknown>;
  requested_at: string;
}

// POST /v1/todo-activations: async activation with resource admission.
// Returns accepted | resource_wait | rejected_permanent (per §12.3 states).
app.post("/v1/todo-activations", async (c) => {
  const tenantId = c.get("tenantId");

  let req: TodoActivationRequest;
  try {
    req = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }
  if (!req.activation_id || !req.goal_id || !req.todo_id) {
    return c.json({detail: "activation_id, goal_id, todo_id are required"}, 422);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: req.goal_id});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "rejected_permanent",
      reason_code: "goal_not_found",
      created_at: new Date().toISOString(),
    }, 404);
  }

  // Check idempotency via readReceipt.
  const operationId = `activation:${req.activation_id}`;
  const existing = await store.readReceipt(operationId);
  if (existing.status === "found") {
    const prior = existing.receipts as Array<{status?: string; reason_code?: string}>;
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: prior[0]?.status ?? "accepted",
      reason_code: prior[0]?.reason_code,
      created_at: new Date().toISOString(),
    });
  }

  // Resource admission: check if the Goal has capacity for a new activation.
  // Simplified v1: accept if goal exists and todo is in the projection.
  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos as Array<{todo_id: string; status: string}> : [];
  const targetTodo = todos.find(t => t.todo_id === req.todo_id);

  if (!targetTodo) {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "rejected_permanent",
      reason_code: "todo_not_found",
      created_at: new Date().toISOString(),
    }, 404);
  }

  if (targetTodo.status === "done") {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "rejected_permanent",
      reason_code: "todo_already_completed",
      created_at: new Date().toISOString(),
    }, 409);
  }

  // Quota check (design §4: Tenant/Goal 配额).
  const quota = (currentHead.quota as GoalQuota | undefined) ?? {
    max_activations: 100, max_active_leases: 10,
    current_activations: 0, current_active_leases: 0,
  };
  if (quota.current_activations >= quota.max_activations) {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "resource_wait",
      reason_code: "quota_activations_exhausted",
      created_at: new Date().toISOString(),
    }, 429);
  }

  // Accepted: store activation receipt atomically + increment quota counter.
  const updatedQuota = { ...quota, current_activations: quota.current_activations + 1 };
  const nextHead = { ...currentHead, quota: updatedQuota };
  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: [{
      type: "TodoActivated",
      payload: {
        activation_id: req.activation_id,
        todo_id: req.todo_id,
        source_commit_sha: req.source_commit_sha,
        manifest_sha256: req.manifest_sha256,
        requested_at: req.requested_at,
      } as unknown as Record<string, unknown>,
    }],
    next_projection: nextHead,
    receipts: [{
      operation_id: operationId,
      status: "accepted",
      activation_id: req.activation_id,
    }],
  });

  if (commitResult.status === "applied") {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "accepted",
      created_at: new Date().toISOString(),
    }, 201);
  }
  if (commitResult.status === "conflict") {
    return c.json({
      schema_version: "todo_activation_receipt_v1",
      activation_id: req.activation_id,
      tenant_id: tenantId,
      status: "resource_wait",
      reason_code: "concurrent_modification",
      created_at: new Date().toISOString(),
    }, 409);
  }
  return c.json({
    schema_version: "todo_activation_receipt_v1",
    activation_id: req.activation_id,
    tenant_id: tenantId,
    status: "rejected_permanent",
    reason_code: "internal_error",
    created_at: new Date().toISOString(),
  }, 500);
});

// POST /v1/todo-activations/:activationId/ack: acknowledge an activation receipt.
app.post("/v1/todo-activations/:activationId/ack", async (c) => {
  const tenantId = c.get("tenantId");
  const activationId = c.req.param("activationId");

  // Verify the activation exists in our event log.
  const operationId = `activation:${activationId}`;

  // Search across known goals — in production use a dedicated lookup table.
  const goalId = c.req.query("goal_id") ?? "";
  if (!goalId) {
    return c.json({detail: "goal_id query parameter required for ack"}, 422);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const existing = await store.readReceipt(operationId);
  if (existing.status !== "found") {
    return c.json({detail: "activation not found"}, 404);
  }

  return c.json({
    schema_version: "loopx_command_receipt_v1",
    command_type: "ack_todo_activation",
    command_id: activationId,
    status: "accepted",
    received_at: new Date().toISOString(),
  });
});

// ─── Human Gate: manual approval for high-risk operations (§14.2.4) ──────────

// POST /v1/goals/:goalId/gates/:gateId/approve
// Marks a human gate as approved. Only approved gates allow downstream Todos to proceed.
app.post("/v1/goals/:goalId/gates/:gateId/approve", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");
  const gateId = c.req.param("gateId");

  interface GateApproval {
    approved_by: string;
    reason?: string;
  }
  let body: GateApproval;
  try {
    body = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }
  if (!body.approved_by) {
    return c.json({detail: "approved_by is required"}, 422);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;

  // Store gate approvals in projection.
  const gates = Array.isArray(currentHead.human_gates)
    ? [...currentHead.human_gates] as Array<{gate_id: string; approved: boolean; approved_by?: string; approved_at?: string}>
    : [];
  const existing = gates.find(g => g.gate_id === gateId);
  if (existing?.approved) {
    return c.json({status: "already_approved", gate_id: gateId, approved_by: existing.approved_by});
  }

  if (existing) {
    existing.approved = true;
    existing.approved_by = body.approved_by;
    existing.approved_at = new Date().toISOString();
  } else {
    gates.push({
      gate_id: gateId,
      approved: true,
      approved_by: body.approved_by,
      approved_at: new Date().toISOString(),
    });
  }

  const nextProjection = {...currentHead, human_gates: gates};
  const operationId = `gate-approve:${gateId}:${Date.now()}`;

  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: [{
      type: "HumanGateApproved",
      payload: {gate_id: gateId, approved_by: body.approved_by, reason: body.reason ?? ""} as unknown as Record<string, unknown>,
    }],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({status: "approved", gate_id: gateId, approved_by: body.approved_by});
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// GET /v1/goals/:goalId/gates — list all human gates and their status.
app.get("/v1/goals/:goalId/gates", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") {
    return c.json({detail: "goal not found"}, 404);
  }
  const currentHead = head.head as Record<string, unknown>;
  const gates = Array.isArray(currentHead.human_gates) ? currentHead.human_gates : [];
  const todos = Array.isArray(currentHead.todos) ? currentHead.todos as Array<{todo_id: string; stage_id?: string}> : [];
  const deps = Array.isArray(currentHead.todo_dependencies) ? currentHead.todo_dependencies as TodoDependencyEdge[] : [];

  // Compute which gates are blocking.
  const gateStatus = gates.map(g => ({
    ...g,
    blocking_todos: deps
      .filter(d => d.gate_id === g.gate_id)
      .map(d => d.downstream_todo_id),
  }));

  // Also show implicit gates from gate_acceptance dependencies.
  const implicitGates = deps
    .filter(d => d.dependency_type === "gate_acceptance" && d.gate_id)
    .filter(d => !gates.some(g => g.gate_id === d.gate_id))
    .map(d => ({
      gate_id: d.gate_id,
      approved: false,
      blocking_todos: [d.downstream_todo_id],
      implicit: true,
    }));

  return c.json({gates: [...gateStatus, ...implicitGates]});
});

// ─── ExecutionPlan workflow (design §5: draft → validate → approve → start) ──

interface ExecutionPlanDraft {
  plan_id: string;
  template_id: string;
  template_version: string;
  goal_id: string;
  sample_name: string;
  depth_tier: "A" | "B" | "C";
  stages: string[];
  policy?: Record<string, unknown>;
  tool_permissions?: string[];
  budget?: Record<string, unknown>;
}

// POST /v1/execution-plans — CreateExecutionPlanDraft
app.post("/v1/execution-plans", async (c) => {
  const tenantId = c.get("tenantId");

  let draft: ExecutionPlanDraft;
  try {
    draft = await c.req.json();
  } catch {
    return c.json({detail: "invalid JSON body"}, 400);
  }
  if (!draft.plan_id || !draft.template_id || !draft.goal_id || !draft.stages?.length) {
    return c.json({detail: "plan_id, template_id, goal_id, stages are required"}, 422);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: draft.goal_id});
  const head = await store.loadAuthority();
  const expectedRevision = head.status === "loaded" ? head.provider_revision : null;
  const currentHead = head.status === "loaded" ? head.head as Record<string, unknown> : {};

  // Check for existing plans.
  const plans = Array.isArray(currentHead.execution_plans)
    ? [...currentHead.execution_plans] as Array<{plan_id: string; status: string}>
    : [];
  if (plans.some(p => p.plan_id === draft.plan_id)) {
    return c.json({detail: `plan already exists: ${draft.plan_id}`}, 409);
  }

  const planRevision = {
    plan_id: draft.plan_id,
    plan_revision: 1,
    template_id: draft.template_id,
    template_version: draft.template_version ?? "1.0.0",
    goal_id: draft.goal_id,
    status: "draft" as const,
    sample_name: draft.sample_name,
    depth_tier: draft.depth_tier,
    stages: draft.stages,
    policy: draft.policy ?? {},
    tool_permissions: draft.tool_permissions ?? [],
    budget: draft.budget ?? {},
    created_at: new Date().toISOString(),
    approved_by: null,
    approved_at: null,
  };

  plans.push(planRevision);
  const nextProjection = {...currentHead, execution_plans: plans};
  const operationId = `plan-create:${draft.plan_id}:rev1`;

  const commitResult = await store.commitAuthority({
    expected_provider_revision: expectedRevision,
    operation_id: operationId,
    events: [{type: "ExecutionPlanDraftCreated", payload: planRevision as unknown as Record<string, unknown>}],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({
      plan_id: draft.plan_id,
      plan_revision: 1,
      status: "draft",
      goal_id: draft.goal_id,
    }, 201);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// POST /v1/execution-plans/:planId/validate — ValidateExecutionPlan
app.post("/v1/execution-plans/:planId/validate", async (c) => {
  const tenantId = c.get("tenantId");
  const planId = c.req.param("planId");

  const goalId = c.req.query("goal_id") ?? "";
  if (!goalId) return c.json({detail: "goal_id query parameter required"}, 422);

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") return c.json({detail: "goal not found"}, 404);

  const currentHead = head.head as Record<string, unknown>;
  const plans = Array.isArray(currentHead.execution_plans)
    ? currentHead.execution_plans as Array<Record<string, unknown> & {plan_id: string; status: string; stages?: string[]}>
    : [];
  const plan = plans.find(p => p.plan_id === planId);
  if (!plan) return c.json({detail: `plan not found: ${planId}`}, 404);
  if (plan.status !== "draft") return c.json({detail: `plan status is ${plan.status}, expected draft`}, 409);

  // Validate required fields.
  const errors: string[] = [];
  if (!plan.sample_name) errors.push("sample_name is required");
  if (!plan.depth_tier) errors.push("depth_tier is required");
  if (!Array.isArray(plan.stages) || (plan.stages as string[]).length === 0) errors.push("stages must be non-empty");
  if (!plan.template_id) errors.push("template_id is required");

  return c.json({
    plan_id: planId,
    valid: errors.length === 0,
    errors,
    checked_at: new Date().toISOString(),
  });
});

// POST /v1/execution-plans/:planId/approve-and-start — ApproveAndStartExecutionPlan
app.post("/v1/execution-plans/:planId/approve-and-start", async (c) => {
  const tenantId = c.get("tenantId");
  const planId = c.req.param("planId");
  const goalId = c.req.query("goal_id") ?? "";
  if (!goalId) return c.json({detail: "goal_id query parameter required"}, 422);

  interface ApproveRequest { approved_by: string; }
  let body: ApproveRequest;
  try { body = await c.req.json(); } catch { return c.json({detail: "invalid JSON body"}, 400); }
  if (!body.approved_by) return c.json({detail: "approved_by is required"}, 422);

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") return c.json({detail: "goal not found"}, 404);
  const currentHead = head.head as Record<string, unknown>;

  const plans = Array.isArray(currentHead.execution_plans)
    ? [...currentHead.execution_plans] as Array<Record<string, unknown> & {plan_id: string; status: string}>
    : [];
  const plan = plans.find(p => p.plan_id === planId);
  if (!plan) return c.json({detail: `plan not found: ${planId}`}, 404);
  if (plan.status !== "draft") return c.json({detail: `plan status is ${plan.status}, expected draft`}, 409);

  // Approve: transition to approved.
  plan.status = "approved";
  plan.approved_by = body.approved_by;
  plan.approved_at = new Date().toISOString();

  // Trigger compile if compile endpoint data is present.
  const stages = plan.stages as string[] ?? [];
  const depthTier = plan.depth_tier as string ?? "A";
  const sampleName = plan.sample_name as string ?? "unknown";
  const compiled = compileTodoBundle({sample_name: sampleName, depth_tier: depthTier as "A" | "B" | "C", stages});

  // Merge todos into projection.
  const existingTodos = Array.isArray(currentHead.todos) ? [...currentHead.todos] as Array<{todo_id: string}> : [];
  const existingIds = new Set(existingTodos.map(t => t.todo_id));
  const newTodos = compiled.todos.filter(t => !existingIds.has(t.todo_id));
  const allTodos = [...existingTodos, ...newTodos.map(t => ({
    schema_version: "todo_item_v0", ...t,
    priority: null, title: null, action_kind: null, task_domain: null,
    capability_binding_ref: null, task_repository: null,
    continuation_policy: null, removed_continuation_policy: null, excluded_agents: [],
  }))];
  allTodos.sort((a, b) => a.todo_id.localeCompare(b.todo_id));

  // Merge dependencies.
  const existingDeps = Array.isArray(currentHead.todo_dependencies)
    ? [...currentHead.todo_dependencies] as TodoDependencyEdge[] : [];
  const depKeys = new Set(existingDeps.map(d => `${d.upstream_todo_id}->${d.downstream_todo_id}`));
  const newDeps = compiled.dependencies.filter(d => !depKeys.has(`${d.upstream_todo_id}->${d.downstream_todo_id}`));
  const allDeps = [...existingDeps, ...newDeps];

  const readModel = coordinationTodoReadModel(
    allTodos as unknown as Array<Record<string, unknown>>,
    TODO_CANONICAL_READ_RECORD_SCHEMA,
  );

  const nextProjection = {
    ...currentHead,
    execution_plans: plans,
    goal_id: goalId,
    todos: allTodos,
    leases: Array.isArray(currentHead.leases) ? currentHead.leases : [],
    todo_dependencies: allDeps,
    todo_read_model: readModel,
  };

  const operationId = `plan-approve:${planId}:rev${plan.plan_revision}`;

  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: [
      {type: "PlanRevisionApproved", payload: {plan_id: planId, approved_by: body.approved_by}},
      {type: "InitialTodoSeeded", payload: {todo_count: newTodos.length, dep_count: newDeps.length}},
    ],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "approved_and_started"}],
  });

  if (commitResult.status === "applied") {
    return c.json({
      plan_id: planId,
      status: "approved",
      approved_by: body.approved_by,
      todos_compiled: newTodos.length,
      dependencies_compiled: newDeps.length,
      total_todos: allTodos.length,
    }, 200);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// GET /v1/goals/:goalId/dependency-snapshot — read-only query
app.get("/v1/goals/:goalId/dependency-snapshot", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") return c.json({detail: "goal not found"}, 404);
  const currentHead = head.head as Record<string, unknown>;

  const todos = Array.isArray(currentHead.todos) ? currentHead.todos : [];
  const deps = Array.isArray(currentHead.todo_dependencies) ? currentHead.todo_dependencies : [];
  const gates = Array.isArray(currentHead.human_gates) ? currentHead.human_gates : [];

  return c.json({
    goal_id: goalId,
    cursor: head.cursor,
    provider_revision: head.provider_revision,
    todos,
    dependencies: deps,
    human_gates: gates,
    snapshot_at: new Date().toISOString(),
  });
});

// ─── Quota management (design §4: Tenant/Goal 配额快照) ─────────────────────

interface GoalQuota {
  max_activations: number;         // max total TodoActivations for this Goal
  max_active_leases: number;       // max concurrent active leases
  current_activations: number;     // counter (maintained by activation commits)
  current_active_leases: number;   // gauge (computed from projection leases)
}

// POST /v1/goals/:goalId/quota — Set or update quota limits.
app.post("/v1/goals/:goalId/quota", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  interface QuotaLimits { max_activations?: number; max_active_leases?: number; }
  let body: QuotaLimits;
  try { body = await c.req.json(); } catch { return c.json({detail: "invalid JSON body"}, 400); }
  if (body.max_activations === undefined && body.max_active_leases === undefined) {
    return c.json({detail: "at least one of max_activations or max_active_leases is required"}, 422);
  }

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  const expectedRevision = head.status === "loaded" ? head.provider_revision : null;
  const currentHead = head.status === "loaded" ? head.head as Record<string, unknown> : {};

  const existing = (currentHead.quota as GoalQuota | undefined) ?? {
    max_activations: 100, max_active_leases: 10,
    current_activations: 0, current_active_leases: 0,
  };

  const quota: GoalQuota = {
    ...existing,
    max_activations: body.max_activations ?? existing.max_activations,
    max_active_leases: body.max_active_leases ?? existing.max_active_leases,
  };

  const nextProjection = {...currentHead, quota};
  const operationId = `quota-set:${Date.now()}`;
  const commitResult = await store.commitAuthority({
    expected_provider_revision: expectedRevision,
    operation_id: operationId,
    events: [{type: "QuotaUpdated", payload: quota as unknown as Record<string, unknown>}],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return c.json({status: "updated", quota}, 200);
  }
  return c.json({detail: "commit failed", reason: commitResult.status}, 500);
});

// GET /v1/goals/:goalId/quota — Get current quota status.
app.get("/v1/goals/:goalId/quota", async (c) => {
  const tenantId = c.get("tenantId");
  const goalId = c.req.param("goalId");

  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") return c.json({detail: "goal not found"}, 404);

  const currentHead = head.head as Record<string, unknown>;
  const quota = (currentHead.quota as GoalQuota | undefined) ?? {
    max_activations: 100, max_active_leases: 10,
    current_activations: 0, current_active_leases: 0,
  };

  // Compute current_active_leases from projection.
  const leases = Array.isArray(currentHead.leases) ? currentHead.leases : [];
  const activeLeases = leases.filter((l: Record<string, unknown>) =>
    l.status === "active" || l.claimed_by !== null
  ).length;

  return c.json({
    goal_id: goalId,
    ...quota,
    current_active_leases: activeLeases,
    activations_remaining: Math.max(0, quota.max_activations - quota.current_activations),
    leases_remaining: Math.max(0, quota.max_active_leases - activeLeases),
  });
});

// ─── Auto-gate: process receipt → gate transition (Phase 5) ──────────────────

async function processGateTransition(
  tenantId: string,
  goalId: string,
  receipt: PlatformAnalysisReceipt,
): Promise<{transition: string; from?: string; to?: string} | null> {
  const store = new PostgreSqlAuthorityStore(database, {tenant_id: tenantId, goal_id: goalId});
  const head = await store.loadAuthority();
  if (head.status !== "loaded") return null;

  const currentHead = head.head as Record<string, unknown>;
  const todos = Array.isArray(currentHead.todos)
    ? currentHead.todos as Array<{todo_id: string; stage_id?: string; status: string; done?: boolean}>
    : [];
  const stages = [...new Set(todos.map(t => t.stage_id).filter(Boolean))] as string[];
  if (stages.length === 0) return null;

  const transition = convertGateReceipt(receipt as unknown as PlatformAnalysisReceiptInput, stages);
  if (transition.action === "no_change") return {transition: "no_change"};

  let updatedTodos = todos;
  if (transition.action === "advance_stage" || transition.action === "complete_goal") {
    const targetStage = transition.action === "advance_stage" ? transition.from_stage : transition.stage;
    updatedTodos = todos.map(t =>
      t.stage_id === targetStage ? {...t, status: "done", done: true} : t
    );
  } else if (transition.action === "block") {
    updatedTodos = todos.map(t =>
      t.stage_id === transition.stage ? {...t, status: "blocked"} : t
    );
  }

  const sortedTodos = [...updatedTodos].sort((a, b) => a.todo_id.localeCompare(b.todo_id));
  const readModel = coordinationTodoReadModel(
    sortedTodos as unknown as Array<Record<string, unknown>>,
    TODO_CANONICAL_READ_RECORD_SCHEMA,
  );
  const nextProjection = {...currentHead, todos: sortedTodos, todo_read_model: readModel};
  const operationId = `gate-auto:${receipt.idempotency_key}`;

  // Idempotency check.
  const existing = await store.readReceipt(operationId);
  if (existing.status === "found") return {transition: "duplicate"};

  const commitResult = await store.commitAuthority({
    expected_provider_revision: head.provider_revision,
    operation_id: operationId,
    events: [{type: `GateTransition:${transition.action}`, payload: {receipt_key: receipt.idempotency_key}}],
    next_projection: nextProjection,
    receipts: [{operation_id: operationId, status: "applied"}],
  });

  if (commitResult.status === "applied") {
    return {
      transition: transition.action,
      from: "from_stage" in transition ? transition.from_stage : undefined,
      to: "to_stage" in transition ? transition.to_stage : undefined,
    };
  }
  return null;
}

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
