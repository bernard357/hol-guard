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
//! - the resident's `LocalCliHook` step `local_cli_hook_op::run_refined`,
//!   under the shared storage hold, for the command, its launch directory,
//!   the daemon's home and environment and the agent's `PATH`: it records
//!   the launch, which refreshes a package script's command catalog, then
//!   reads the grant, so a grant is matched against the catalog the daemon's
//!   call would have written;
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
    GuardHookEnvelopeV2, GuardHookLocalCliRulesV1, GuardHookSourceMetadataV2,
    LocalCliHookRequestV1, LOCAL_CLI_HOOK_REQUEST_SCHEMA,
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
const STORE_SOURCE: &str = "default";
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
    let request = GrantRequest {
        harness,
        payload: envelope.raw_payload.as_object()?,
        result,
        source: &envelope.source,
        rules,
        sink_command: &sink.sink_command,
        deadline: deadline(envelope, started),
    };
    match granted(&request)? {
        Granted::Routed(routed) => {
            *harness_response = Some(routed);
            Some(ROUTED)
        }
        Granted::Kept(receipt) => {
            *harness_response = Some(receipt);
            Some(KEPT)
        }
        Granted::Declined => Some(DECLINED),
    }
}

/// A grant-routed `PreToolUse` with what the grant step reads: the call, the
/// review the edge produced for it, where it runs, the daemon's rules and the
/// argv that starts Guard's CLI.
pub(crate) struct GrantRequest<'a> {
    pub(crate) harness: &'a str,
    pub(crate) payload: &'a Map<String, Value>,
    pub(crate) result: &'a Value,
    pub(crate) source: &'a GuardHookSourceMetadataV2,
    pub(crate) rules: &'a GuardHookLocalCliRulesV1,
    pub(crate) sink_command: &'a [String],
    /// When the grant step must have answered.
    pub(crate) deadline: Instant,
}

/// The grant step's answer to a grant-routed `PreToolUse`.
#[derive(Debug, PartialEq)]
pub(crate) enum Granted {
    /// The allow that runs the call in the grant's sandbox.
    Routed(Value),
    /// The granted sandbox receipt, for a receipt-only call.
    Kept(Value),
    /// No grant routes the call, so the review stands.
    Declined,
}

/// `edge_granted_containment_response` for `request`, or `None` when the
/// grant step or its rewrite fails or does not finish by its deadline.
pub(crate) fn granted(request: &GrantRequest<'_>) -> Option<Granted> {
    let result = request.result.as_object()?;
    let local = match local_request(request.source, request.payload, request.rules) {
        Ok(Some(local)) => local,
        // No command or launch directory: the daemon finds no grant either.
        Ok(None) => return Some(Granted::Declined),
        Err(()) => return None,
    };
    let wait = request
        .deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())?;
    let Some(refined) = decided(local, wait)? else {
        return Some(Granted::Declined);
    };
    if refined.action != ALLOW_CONTAINED_WITH_GRANT || refined.contained_grant.is_none() {
        return Some(Granted::Declined);
    }
    let Value::Object(route) = contained_route() else {
        return None;
    };
    let mut granted = result.clone();
    granted.extend(route);
    let receipt = pre_tool(request.harness, &granted);
    let inputs = inputs(
        request.source,
        request.harness,
        request.payload,
        &receipt,
        request.sink_command,
    );
    let rewrite = containment_rewrite(&inputs).ok()?;
    if rewrite.kept_because.as_deref() == Some(RECEIPT_ONLY) {
        // The sink re-authorizing gets the sandbox receipt itself.
        return Some(Granted::Kept(Value::Object(receipt)));
    }
    Some(match rewrite.response {
        Some(routed) => Granted::Routed(routed),
        None => Granted::Declined,
    })
}

/// The `LocalCliHook` request the daemon sends for the grant: the command,
/// its resolved launch directory, the daemon's home and environment with the
/// agent's `PATH`, held at an outside-roots review. `Ok(None)` when the call
/// names no command or launches nowhere the daemon could resolve.
fn local_request(
    source: &GuardHookSourceMetadataV2,
    payload: &Map<String, Value>,
    rules: &GuardHookLocalCliRulesV1,
) -> Result<Option<LocalCliHookRequestV1>, ()> {
    let Some(command) = pre_tool_command(payload)? else {
        return Ok(None);
    };
    let workspace = source.cwd.as_deref().unwrap_or_default();
    let Some(cwd) = resolve_launch_dir(launch_dir_candidate(payload, workspace)?)? else {
        return Ok(None);
    };
    let mut env = rules.env.clone();
    if let Some(path) = source
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
        guard_home: source.guard_home.clone(),
        // `GuardStore.guard_source` is not read by the observation writes.
        source: STORE_SOURCE.to_owned(),
        busy_timeout_ms: u64::from(timeout_ms).clamp(1, crate::guard_store_op::MAX_BUSY_TIMEOUT_MS),
        command: command.to_owned(),
        cwd,
        home_dir: Some(source.home_dir.clone()),
        user_home: rules.user_home.clone(),
        env,
        current_action: "review".to_owned(),
        current_reason_code: Some(OUTSIDE_ROOTS_REASON.to_owned()),
        grant_allowed: true,
    }))
}

/// When the edge's grant step must have answered: the review's budget plus
/// `GRANT_WAIT`, counted from when the edge began the hook.
fn deadline(envelope: &GuardHookEnvelopeV2, started: Instant) -> Instant {
    let budget = envelope
        .deadline_budget_ms
        .unwrap_or(DEFAULT_DEADLINE_BUDGET_MS)
        .clamp(1, MAX_DEADLINE_BUDGET_MS);
    started + Duration::from_millis(budget) + GRANT_WAIT
}

/// The `LocalCliHook` step under the shared storage hold, as the daemon's
/// resident call runs it, with the store files put back into private mode
/// after it. `Some(None)` when the store holds no grant row, so no grant can
/// route the call; `None` when the hold cannot be taken, the step fails, or
/// its answer does not arrive within `wait`.
fn decided(
    request: LocalCliHookRequestV1,
    wait: Duration,
) -> Option<Option<crate::local_cli_hook_contained::Refined>> {
    let gate_wait = wait.min(STORAGE_GATE_WAIT);
    let (sender, receiver) = mpsc::sync_channel(1);
    // An abandoned step finishes on its own and its answer is dropped.
    std::thread::Builder::new()
        .name(REQUEST_ID.to_owned())
        .spawn(move || {
            let guard_home = Path::new(&request.guard_home);
            let answer = {
                let Ok(_hold) =
                    crate::hook_evidence_store_gate::hold_storage_gate(guard_home, gate_wait)
                else {
                    return;
                };
                // Read under the hold, so a writer adding a grant finishes
                // first. An unreadable store counts as holding a row, so the
                // step decides it.
                if has_grant_rows_at(&request.store_path, &request.guard_home) {
                    crate::local_cli_hook_op::run_refined(&request).map(Some)
                } else {
                    Ok(None)
                }
            };
            crate::hook_direct::saved_decision::consume::repair_store_permissions(guard_home);
            let _ = sender.send(answer);
        })
        .ok()?;
    receiver.recv_timeout(wait).ok()?.ok()
}

#[cfg(all(test, unix))]
#[path = "edge_containment_grant_tests.rs"]
mod tests;
