/** Phase 5: Reverse Analysis Capability — Todo bundle compiler + Gate Receipt converter.
 *
 * Design refs: 08-LoopX控制内核设计.md §11.4, §12
 *
 * Bundle pattern (§11.4):
 *   L(N)-(X) Gate → L(N)-(X+1) Todo bundle
 *   Same depth tier modules can run in parallel; stage progression is serial.
 *
 * Gate Receipt conversion (§12.4):
 *   PlatformAnalysisReceipt (status + gate receipt) → LoopX Gate state transition
 */

// ─── Todo Bundle Compiler ─────────────────────────────────────────────────────

export interface GoalSpec {
  sample_name: string;
  depth_tier: "A" | "B" | "C";
  stages: string[];  // e.g. ["L0", "L2", "L3"]
}

export interface CompiledTodo {
  todo_id: string;
  index: number;
  done: boolean;
  text: string;
  role: string;
  status: string;
  archive_state: string;
  source_section: string;
  task_class: string;
  stage_id: string;
  depth_tier: string;
  claimed_by: string | null;
}

export interface CompiledDependency {
  upstream_todo_id: string;
  downstream_todo_id: string;
  dependency_type: "hard_completion" | "gate_acceptance" | "source_commit_current";
  upstream_commit_sha: string | null;
  gate_id: string | null;
}

/** Generate L0-L7 Todo bundle for a GoalSpec with proper serial dependencies.
 *
 * Stage progression: serial via hard_completion + gate_acceptance.
 * Same-stage modules: parallel (no cross-dependency within same stage+tier).
 */
export function compileTodoBundle(spec: GoalSpec): {
  todos: CompiledTodo[];
  dependencies: CompiledDependency[];
} {
  const todos: CompiledTodo[] = [];
  const dependencies: CompiledDependency[] = [];
  let index = 0;

  const stageIds = spec.stages;
  for (let s = 0; s < stageIds.length; s++) {
    const stageId = stageIds[s];
    const todoId = `todo_${stageId.toLowerCase()}_${spec.depth_tier.toLowerCase()}_${sanitize(spec.sample_name)}`;
    const prevTodoId = s > 0
      ? `todo_${stageIds[s - 1].toLowerCase()}_${spec.depth_tier.toLowerCase()}_${sanitize(spec.sample_name)}`
      : null;

    todos.push({
      todo_id: todoId,
      index: index++,
      done: false,
      text: `${stageId} ${spec.depth_tier} analysis of ${spec.sample_name}`,
      role: "agent",
      status: "open",
      archive_state: "active",
      source_section: "Agent Todo",
      task_class: "advancement_task",
      stage_id: stageId,
      depth_tier: spec.depth_tier,
      claimed_by: null,
    });

    // Serial dependency: previous stage must complete before this one starts.
    if (prevTodoId) {
      dependencies.push({
        upstream_todo_id: prevTodoId,
        downstream_todo_id: todoId,
        dependency_type: "hard_completion",
        upstream_commit_sha: null,
        gate_id: `gate_${stageIds[s - 1].toLowerCase()}_${spec.depth_tier.toLowerCase()}`,
      });
    }
  }

  return {todos, dependencies};
}

function sanitize(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9_-]/g, "_").slice(0, 32);
}

// ─── Gate Receipt Converter ──────────────────────────────────────────────────

export interface PlatformAnalysisReceiptInput {
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
  status: string;  // completed | partial | blocked | failed
  next_action?: {type: string; target_stage_id?: string; reason?: string};
  idempotency_key: string;
}

export type GateTransition =
  | {action: "advance_stage"; from_stage: string; to_stage: string; gate_id: string}
  | {action: "request_deeper"; from_stage: string; to_tier: string; gate_id: string}
  | {action: "block"; stage: string; reason: string}
  | {action: "complete_goal"; stage: string}
  | {action: "no_change"; reason: string};

/** Convert a PlatformAnalysisReceipt to a LoopX Gate transition.
 *
 * Per §12.4: the receipt drives Gate state, which drives the next stage bundle.
 *   completed + advance → close current gate, open next stage
 *   partial + request_deeper → stay, request deeper tier
 *   blocked/failed → block stage
 */
export function convertGateReceipt(
  receipt: PlatformAnalysisReceiptInput,
  stages: readonly string[],
): GateTransition {
  const stageIndex = stages.indexOf(receipt.stage_id);
  if (stageIndex === -1) {
    return {action: "no_change", reason: `unknown stage: ${receipt.stage_id}`};
  }

  switch (receipt.status) {
    case "completed": {
      // Check if there's a next stage.
      if (receipt.next_action?.type === "advance" && stageIndex < stages.length - 1) {
        const nextStage = stages[stageIndex + 1];
        return {
          action: "advance_stage",
          from_stage: receipt.stage_id,
          to_stage: nextStage,
          gate_id: `gate_${receipt.stage_id.toLowerCase()}_${receipt.depth_tier.toLowerCase()}`,
        };
      }
      if (stageIndex === stages.length - 1) {
        return {action: "complete_goal", stage: receipt.stage_id};
      }
      return {action: "no_change", reason: "completed but no next_action.advance"};
    }
    case "partial": {
      if (receipt.next_action?.type === "request_deeper") {
        const deeperTier = receipt.depth_tier === "A" ? "B" : receipt.depth_tier === "B" ? "C" : "C";
        return {
          action: "request_deeper",
          from_stage: receipt.stage_id,
          to_tier: deeperTier,
          gate_id: `gate_${receipt.stage_id.toLowerCase()}_${deeperTier.toLowerCase()}`,
        };
      }
      return {action: "block", stage: receipt.stage_id, reason: "partial without deeper request"};
    }
    case "blocked":
      return {action: "block", stage: receipt.stage_id, reason: receipt.next_action?.reason ?? "blocked"};
    case "failed":
      return {action: "block", stage: receipt.stage_id, reason: receipt.next_action?.reason ?? "analysis failed"};
    default:
      return {action: "no_change", reason: `unknown status: ${receipt.status}`};
  }
}
