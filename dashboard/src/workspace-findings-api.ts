import { fetchGuardApi } from "./guard-api";

const ASSESSMENTS_PATH = "/v1/supply-chain/workspace-assessments";
const FINDINGS_PATH = "/v1/supply-chain/workspace-findings";

export type WorktreeKeys = { codebaseKey: string; worktreeKey: string };

export type WorkspaceWorktree = WorktreeKeys & {
  root: string;
  stale: boolean;
  paused: boolean;
  lastScanAtMs: number | null;
};

export type WorkspaceRunState = "queued" | "running" | "completed" | "partial" | "superseded" | "failed" | "canceled";

export type WorkspaceRun = WorktreeKeys & {
  runId: string;
  state: WorkspaceRunState;
  triggerKind: string;
  errorCode: string | null;
  finishedAtMs: number | null;
};

export type WorkspaceFinding = {
  findingId: string;
  severity: string;
  decision: string;
  ecosystem: string;
  packageName: string;
  packageVersion: string | null;
  fixVersion: string | null;
  advisoryIds: string[];
};

export type WorkspaceAssessment = WorktreeKeys & {
  runId: string;
  partial: boolean;
  reasons: string[];
  notRun: string[];
  finishedAtMs: number | null;
  findings: WorkspaceFinding[];
};

export type WorkspaceFindingsState = {
  worktrees: WorkspaceWorktree[];
  runs: WorkspaceRun[];
  assessments: WorkspaceAssessment[];
};

const RUN_STATES = new Set<string>(["queued", "running", "completed", "partial", "superseded", "failed", "canceled"]);

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function keys(item: Record<string, unknown>): WorktreeKeys | null {
  const codebaseKey = text(item.codebase_key);
  const worktreeKey = text(item.worktree_key);
  return codebaseKey && worktreeKey ? { codebaseKey, worktreeKey } : null;
}

function normalizeWorktree(value: unknown): WorkspaceWorktree | null {
  const item = record(value);
  const ids = keys(item);
  if (ids === null) return null;
  return {
    ...ids,
    root: text(item.root) ?? "",
    stale: item.stale === true,
    paused: item.paused === true,
    lastScanAtMs: count(item.last_scan_at_ms),
  };
}

function normalizeRun(value: unknown): WorkspaceRun | null {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  const state = text(item.state);
  if (ids === null || runId === null || state === null || !RUN_STATES.has(state)) return null;
  return {
    ...ids,
    runId,
    state: state as WorkspaceRunState,
    triggerKind: text(item.trigger_kind) ?? "manual",
    errorCode: text(item.error_code),
    finishedAtMs: count(item.finished_at_ms),
  };
}

function normalizeFinding(value: unknown): WorkspaceFinding | null {
  const item = record(value);
  const findingId = text(item.finding_id);
  const packageName = text(item.package_name);
  if (findingId === null || packageName === null) return null;
  return {
    findingId,
    severity: text(item.severity) ?? "unknown",
    decision: text(item.decision) ?? "warn",
    ecosystem: text(item.ecosystem) ?? "unknown",
    packageName,
    packageVersion: text(item.package_version),
    fixVersion: text(item.fix_version),
    advisoryIds: list(item.advisory_ids).filter((entry): entry is string => typeof entry === "string"),
  };
}

function normalizeAssessment(value: unknown): WorkspaceAssessment | null {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  if (ids === null || runId === null) return null;
  const coverage = record(item.coverage);
  const detectors = record(coverage.detectors);
  const reasons = list(coverage.reasons).filter(
    (entry): entry is string => typeof entry === "string" && !entry.startsWith("detector_not_run:"),
  );
  const notRun = Object.entries(detectors)
    .filter(([, status]) => status === "not_run")
    .map(([name]) => name);
  // A detector that is not part of the check yet is listed on its own; it does
  // not make every assessment read as partial coverage of what was checked.
  const reportedPartial = item.state === "partial" || coverage.status === "partial";
  return {
    ...ids,
    runId,
    partial: reasons.length > 0 || (reportedPartial && notRun.length === 0),
    reasons,
    notRun,
    finishedAtMs: count(item.finished_at_ms),
    findings: list(item.findings)
      .map(normalizeFinding)
      .filter((entry): entry is WorkspaceFinding => entry !== null),
  };
}

export function normalizeWorkspaceFindingsState(assessmentsPayload: unknown, findingsPayload: unknown): WorkspaceFindingsState {
  const history = record(assessmentsPayload);
  const findings = record(findingsPayload);
  return {
    worktrees: list(findings.worktrees ?? history.worktrees)
      .map(normalizeWorktree)
      .filter((entry): entry is WorkspaceWorktree => entry !== null),
    runs: list(history.runs)
      .map(normalizeRun)
      .filter((entry): entry is WorkspaceRun => entry !== null),
    assessments: list(findings.assessments)
      .map(normalizeAssessment)
      .filter((entry): entry is WorkspaceAssessment => entry !== null),
  };
}

async function readPayload(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const response = await fetchGuardApi(path, init);
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok && response.status !== 409) {
    throw new Error(workspaceErrorMessage(text(record(body).error)));
  }
  return { status: response.status, body };
}

export async function fetchWorkspaceFindings(signal?: AbortSignal): Promise<WorkspaceFindingsState> {
  const [history, findings] = await Promise.all([
    readPayload(ASSESSMENTS_PATH, { signal }),
    readPayload(FINDINGS_PATH, { signal }),
  ]);
  return normalizeWorkspaceFindingsState(history.body, findings.body);
}

function post(path: string, payload: Record<string, string>) {
  return readPayload(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function addWorkspaceForAssessment(root: string): Promise<void> {
  await post(ASSESSMENTS_PATH, { root });
}

export type WorkspaceAction = "run" | "pause" | "resume";

export async function runWorkspaceAction(action: WorkspaceAction, worktree: WorktreeKeys): Promise<void> {
  await post(`${ASSESSMENTS_PATH}/${action}`, {
    codebase_key: worktree.codebaseKey,
    worktree_key: worktree.worktreeKey,
  });
}

const ERROR_MESSAGES: Record<string, string> = {
  invalid_root: "Choose a folder before adding it.",
  workspace_root_not_absolute: "Guard needs the full path to the folder.",
  workspace_root_missing: "That folder no longer exists. Choose it again.",
  workspace_root_not_directory: "That path is a file. Choose its folder instead.",
  invalid_worktree: "This workspace is no longer tracked. Refresh the list.",
};

export function workspaceErrorMessage(code: string | null): string {
  return (code && ERROR_MESSAGES[code]) ?? "Guard could not update workspace assessments. Check that Guard is running, then retry.";
}
