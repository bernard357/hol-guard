//! The contained grant, answered in the edge.
//!
//! A `PreToolUse` the edge routes to the grant is an outside-roots review a
//! local CLI grant on this device may widen the workspace sandbox for. The
//! daemon used to ask the resident for that grant, render the granted
//! receipt and ask `containment_rewrite` for it: three round trips after the
//! edge answered. When the envelope asks for it (`containment_sink.grant`)
//! and carries the daemon's `local_cli_rules`, the edge runs the same steps
//! itself, with the request the daemon would have sent:
//!
//! - the grant refinement `local_cli_hook_op::decide_refined`, under the
//!   shared storage hold, for the command, its launch directory, the
//!   daemon's home and environment and the agent's `PATH`;
//! - an allowed grant copies `contained_route` over the result, and the
//!   receipt is rendered with `pre_tool`, as the resident renders it;
//! - `containment_rewrite` turns that receipt into the routed allow.
//!
//! The answer is a mark on the edge, never a new verdict: `result` and
//! `receipt` stay the review the edge produced. `routed` carries the routed
//! allow, `kept` the granted receipt a receipt-only call asked for, and
//! `declined` means no grant routes the call, so the review stands and pauses
//! for approval with both of its choices. A grant step that fails, cannot
//! take the storage hold or does not finish within the edge's time is not
//! answered, and the daemon asks for the grant as before.

use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use guard_command::hook_responses::pre_tool;
use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookLocalCliRulesV1, LocalCliHookRequestV1,
    LOCAL_CLI_HOOK_REQUEST_SCHEMA,
};
use serde_json::{Map, Value};

use super::{inputs, KEPT, ROUTED};
use crate::hook_decision_containment_rewrite::containment_rewrite;
use crate::hook_direct::local_cli::{launch_dir_candidate, pre_tool_command, resolve_launch_dir};
use crate::hook_direct::{DEFAULT_DEADLINE_BUDGET_MS, MAX_DEADLINE_BUDGET_MS};
use crate::local_cli_hook_contained::{
    contained_route, has_grant_rows_at, ALLOW_CONTAINED_WITH_GRANT, OUTSIDE_ROOTS_REASON,
};

/// `containment_rewrite` when no grant routes the call and the review stands.
pub(super) const DECLINED: &str = "declined";
/// How long the grant step waits for a writer's exclusive storage hold.
const STORAGE_GATE_WAIT: Duration = Duration::from_secs(2);
/// How far past the review's budget the grant step may run. The daemon
/// allows the edge five seconds past that budget when it sends
/// `local_cli_rules`; the rest is the answer's way back.
const GRANT_WAIT: Duration = Duration::from_secs(4);
const REQUEST_ID: &str = "edge-local-cli-grant";
const RECEIPT_ONLY: &str = "receipt_only";

/// The edge's answer to a grant-routed `PreToolUse`, replacing
/// `harness_response` with the routed allow or the granted receipt. `None`
/// when the envelope did not ask for it, Watch only records the call, or the
/// grant step or its rewrite fails or runs out of time.
pub(super) fn answer(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    result: &Value,
    started: Instant,
    harness_response: &mut Option<Value>,
) -> Option<&'static str> {
    let sink = envelope
        .containment_sink
        .as_ref()
        .filter(|sink| sink.grant)?;
    let rules = envelope.local_cli_rules.as_ref()?;
    if envelope.recording_only {
        return None;
    }
    let payload = envelope.raw_payload.as_object()?;
    let result = result.as_object()?;
    let request = match request(envelope, payload, rules) {
        Ok(Some(request)) => request,
        // No command or launch directory: the daemon finds no grant either.
        Ok(None) => return Some(DECLINED),
        Err(()) => return None,
    };
    // Only a CLI with a grant row can be allowed; an unreadable store counts
    // as holding one, so the step below decides it.
    if !has_grant_rows_at(&request.store_path, &request.guard_home) {
        return Some(DECLINED);
    }
    let refined = decided(request, remaining(envelope, started)?)?;
    if refined.action != ALLOW_CONTAINED_WITH_GRANT || refined.contained_grant.is_none() {
        return Some(DECLINED);
    }
    let Value::Object(route) = contained_route() else {
        return None;
    };
    let mut granted = result.clone();
    granted.extend(route);
    let receipt = pre_tool(harness, &granted);
    let inputs = inputs(envelope, harness, payload, &receipt, &sink.sink_command);
    let rewrite = containment_rewrite(&inputs).ok()?;
    if rewrite.kept_because.as_deref() == Some(RECEIPT_ONLY) {
        // The sink re-authorizing gets the sandbox receipt itself.
        *harness_response = Some(Value::Object(receipt));
        return Some(KEPT);
    }
    match rewrite.response {
        Some(routed) => {
            *harness_response = Some(routed);
            Some(ROUTED)
        }
        None => Some(DECLINED),
    }
}

/// The `LocalCliHook` request the daemon sends for the grant: the command,
/// its resolved launch directory, the daemon's home and environment with the
/// agent's `PATH`, held at an outside-roots review. `Ok(None)` when the call
/// names no command or launches nowhere the daemon could resolve.
fn request(
    envelope: &GuardHookEnvelopeV2,
    payload: &Map<String, Value>,
    rules: &GuardHookLocalCliRulesV1,
) -> Result<Option<LocalCliHookRequestV1>, ()> {
    let Some(command) = pre_tool_command(payload)? else {
        return Ok(None);
    };
    let workspace = envelope.source.cwd.as_deref().unwrap_or_default();
    let Some(cwd) = resolve_launch_dir(launch_dir_candidate(payload, workspace)?)? else {
        return Ok(None);
    };
    let mut env = rules.env.clone();
    if let Some(path) = envelope
        .source
        .execution_environment
        .as_ref()
        .map(|environment| environment.path.as_str())
        .filter(|path| !path.is_empty() && !path.contains('\0'))
    {
        env.insert("PATH".to_owned(), path.to_owned());
    }
    let timeout_ms = crate::hook_evidence_store_timeout::sqlite_timeout_ms();
    Ok(Some(LocalCliHookRequestV1 {
        schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        store_path: rules.store_path.clone(),
        guard_home: envelope.source.guard_home.clone(),
        // Nothing is recorded here, so the store's source is never read.
        source: String::new(),
        busy_timeout_ms: u64::from(timeout_ms).clamp(1, crate::guard_store_op::MAX_BUSY_TIMEOUT_MS),
        command: command.to_owned(),
        cwd,
        home_dir: Some(envelope.source.home_dir.clone()),
        user_home: rules.user_home.clone(),
        env,
        current_action: "review".to_owned(),
        current_reason_code: Some(OUTSIDE_ROOTS_REASON.to_owned()),
        grant_allowed: true,
    }))
}

/// The time left for the grant step: the review's budget plus `GRANT_WAIT`,
/// counted from when the edge began the hook. `None` once it has run out.
fn remaining(envelope: &GuardHookEnvelopeV2, started: Instant) -> Option<Duration> {
    let budget = envelope
        .deadline_budget_ms
        .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
        .clamp(1, MAX_DEADLINE_BUDGET_MS);
    (started + Duration::from_millis(budget) + GRANT_WAIT)
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// The grant refinement under the shared storage hold, or `None` when the
/// hold cannot be taken, the store cannot be read, or the answer does not
/// arrive within `wait`.
fn decided(
    request: LocalCliHookRequestV1,
    wait: Duration,
) -> Option<crate::local_cli_hook_contained::Refined> {
    let gate_wait = wait.min(STORAGE_GATE_WAIT);
    let (sender, receiver) = mpsc::sync_channel(1);
    // An abandoned step finishes on its own and its answer is dropped.
    std::thread::Builder::new()
        .name(REQUEST_ID.to_owned())
        .spawn(move || {
            let Ok(_hold) = crate::hook_evidence_store_gate::hold_storage_gate(
                Path::new(&request.guard_home),
                gate_wait,
            ) else {
                return;
            };
            let _ = sender.send(crate::local_cli_hook_op::decide_refined(&request));
        })
        .ok()?;
    receiver.recv_timeout(wait).ok()?.ok()
}

#[cfg(all(test, unix))]
#[path = "edge_containment_grant_tests.rs"]
mod tests;
