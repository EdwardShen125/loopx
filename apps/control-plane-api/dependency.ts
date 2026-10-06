/** Phase 4: Todo Dependency DAG + Backfill propagation.
 *
 * Design refs: 08-LoopX控制内核设计.md §10.2-10.3
 *
 * Three dependency types (v1):
 *   hard_completion       — downstream waits for upstream terminal state
 *   gate_acceptance       — downstream waits for Gate acceptance at revision
 *   source_commit_current — downstream bound to upstream's current Git Commit
 *
 * Backfill propagation (§10.3):
 *   upstream replacement event
 *     → completed downstream → completed_provisional
 *     → in-progress downstream → paused_for_backfill
 *     → needs redo → reopened_backfill
 *     → create successor todo
 *   Propagation never deletes old todos/gates/evidence.
 */

export type DependencyType =
  | "hard_completion"
  | "gate_acceptance"
  | "source_commit_current";

export interface TodoDependencyEdge {
  upstream_todo_id: string;
  downstream_todo_id: string;
  dependency_type: DependencyType;
  upstream_commit_sha: string | null;
  gate_id: string | null;
}

export type BackfillStatus =
  | "completed_provisional"
  | "paused_for_backfill"
  | "reopened_backfill";

/** Determine the backfill status for a downstream todo. */
export function determineBackfillStatus(
  currentStatus: string,
  claimedBy: string | null,
): BackfillStatus {
  if (currentStatus === "completed" || currentStatus === "done") {
    return "completed_provisional";
  }
  if (claimedBy !== null && claimedBy !== undefined && claimedBy !== "") {
    return "paused_for_backfill";
  }
  return "reopened_backfill";
}

/** Find all downstream todos that transitively depend on a given upstream todo. */
export function findDownstream(
  edges: TodoDependencyEdge[],
  upstreamTodoId: string,
): string[] {
  const affected = new Set<string>();
  const queue = [upstreamTodoId];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const edge of edges) {
      if (edge.upstream_todo_id === current && !affected.has(edge.downstream_todo_id)) {
        affected.add(edge.downstream_todo_id);
        queue.push(edge.downstream_todo_id);
      }
    }
  }
  return [...affected];
}

/** Check if a todo is ready to execute (all hard_completion deps are satisfied). */
export function checkReadiness(
  todoId: string,
  todos: Array<{todo_id: string; status: string}>,
  edges: TodoDependencyEdge[],
): {ready: boolean; blocked_by: Array<{todo_id: string; status: string; type: DependencyType}>} {
  const todoMap = new Map(todos.map(t => [t.todo_id, t]));
  const blockedBy: Array<{todo_id: string; status: string; type: DependencyType}> = [];

  for (const edge of edges) {
    if (edge.downstream_todo_id !== todoId) continue;
    const upstream = todoMap.get(edge.upstream_todo_id);
    if (!upstream) continue;

    switch (edge.dependency_type) {
      case "hard_completion":
        if (upstream.status !== "completed" && upstream.status !== "done") {
          blockedBy.push({todo_id: upstream.todo_id, status: upstream.status, type: edge.dependency_type});
        }
        break;
      case "gate_acceptance":
        // Gate acceptance check would look at gate_receipts; simplified for now.
        if (upstream.status !== "completed" && upstream.status !== "done") {
          blockedBy.push({todo_id: upstream.todo_id, status: upstream.status, type: edge.dependency_type});
        }
        break;
      case "source_commit_current":
        // Commit currency requires the upstream commit to still be the head.
        // Simplified: same as hard_completion for v1.
        if (upstream.status !== "completed" && upstream.status !== "done") {
          blockedBy.push({todo_id: upstream.todo_id, status: upstream.status, type: edge.dependency_type});
        }
        break;
    }
  }

  return {ready: blockedBy.length === 0, blocked_by: blockedBy};
}

/** Build the backfill mutation events for downstream todos. */
export function buildBackfillMutations(
  edges: TodoDependencyEdge[],
  upstreamTodoId: string,
  todos: Array<{todo_id: string; status: string; claimed_by: string | null; todo: Record<string, unknown>}>,
): Array<{todo_id: string; old_status: string; new_status: BackfillStatus; todo: Record<string, unknown>}> {
  const downstreamIds = findDownstream(edges, upstreamTodoId);
  const todoMap = new Map(todos.map(t => [t.todo_id, t]));
  const mutations: Array<{todo_id: string; old_status: string; new_status: BackfillStatus; todo: Record<string, unknown>}> = [];

  for (const id of downstreamIds) {
    const t = todoMap.get(id);
    if (!t) continue;
    const newStatus = determineBackfillStatus(t.status, t.claimed_by);
    mutations.push({
      todo_id: id,
      old_status: t.status,
      new_status: newStatus,
      todo: {
        ...(t.todo as Record<string, unknown>),
        status: newStatus,
        backfill_marker: `backfill-from:${upstreamTodoId}`,
      },
    });
  }
  return mutations;
}
