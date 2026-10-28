//! The containment rewrite, answered in the edge.
//!
//! A `PreToolUse` the edge routes to the sink is rewritten into Guard's
//! contained execution sink by `containment_rewrite`. When the daemon sends
//! the argv that starts Guard's CLI (`containment_sink`), the edge asks that
//! rewrite itself, with the facts the daemon would have sent, so the daemon
//! makes one resident call instead of two. The workspace, home and Guard
//! home are the envelope's source.
//!
//! The rewrite never changes the result or the receipt: a call the sink
//! takes comes back as the routed allow (`routed`), and any other keeps its
//! receipt (`kept`). A rewrite that fails is not answered, and the daemon
//! asks the resident as before, so its outage stays the host outage
//! response.

use guard_contracts::{ContainmentRewriteInputsV1, GuardHookEdgeResultV2, GuardHookEnvelopeV2};
use serde_json::{Map, Value};

use crate::hook_decision_containment_rewrite::containment_rewrite;
use crate::hook_decision_containment_route::host_platform;

/// `containment_rewrite` when `harness_response` runs the call in the sink.
pub(super) const ROUTED: &str = "routed";
/// `containment_rewrite` when the receipt stands.
pub(super) const KEPT: &str = "kept";
const SINK_ROUTE: &str = "sink";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
/// A review pauses for approval before any containment step.
const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// Answers `edge.containment_rewrite`, replacing its `harness_response` with
/// the routed allow when the sink takes the call.
pub(super) fn attach(envelope: &GuardHookEnvelopeV2, edge: &mut GuardHookEdgeResultV2) {
    let custom_block = edge
        .local_cli_rule
        .as_ref()
        .is_some_and(|rule| rule.blocked);
    let route = edge.containment_route.as_deref().unwrap_or("none");
    edge.containment_rewrite = rewrite(
        envelope,
        &edge.harness,
        route,
        &edge.result,
        custom_block,
        &mut edge.harness_response,
    )
    .map(str::to_owned);
}

/// The edge's rewrite of a sink-routed `PreToolUse`, replacing
/// `harness_response` with the routed allow when the sink takes the call.
/// `None` when the daemon sent no sink argv, the call is not routed to the
/// sink, a custom block or a review answers it first, or the rewrite fails.
fn rewrite(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    route: &str,
    result: &Value,
    custom_block: bool,
    harness_response: &mut Option<Value>,
) -> Option<&'static str> {
    let sink = envelope.containment_sink.as_ref()?;
    let minimum_action = result.get("minimum_action").and_then(Value::as_str);
    if route != SINK_ROUTE
        || envelope.recording_only
        || custom_block
        || minimum_action.is_some_and(|action| REVIEW_ACTIONS.contains(&action))
    {
        return None;
    }
    let rendered = harness_response.as_ref()?.as_object()?;
    let payload = envelope.raw_payload.as_object()?;
    let inputs = inputs(envelope, harness, payload, rendered, &sink.sink_command);
    match containment_rewrite(&inputs).ok()?.response {
        Some(routed) => {
            *harness_response = Some(routed);
            Some(ROUTED)
        }
        None => Some(KEPT),
    }
}

/// The facts the daemon sends `containment_rewrite`: the call from the
/// payload, the receipt as the harness would read it, and the source.
fn inputs(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    payload: &Map<String, Value>,
    rendered: &Map<String, Value>,
    sink_command: &[String],
) -> ContainmentRewriteInputsV1 {
    let payload_text = |names: &[&str]| {
        first(payload, names)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let payload_value = |names: &[&str]| first(payload, names).cloned().unwrap_or(Value::Null);
    let rendered_text = |name: &str| {
        rendered
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    ContainmentRewriteInputsV1 {
        harness: harness.to_owned(),
        platform: host_platform().to_owned(),
        bridge: false,
        receipt_only: payload.get(RECEIPT_ONLY_FIELD) == Some(&Value::Bool(true)),
        event_name: payload_text(&["hook_event_name", "hookEventName"]),
        tool_name: payload_text(&["tool_name", "toolName"]),
        tool_input: payload_value(&["tool_input", "toolInput"]),
        decision: rendered_text("decision"),
        policy_action: rendered_text("policy_action"),
        reason_code: rendered_text("reason_code"),
        required_execution_profile: rendered_text("required_execution_profile"),
        observe_mode: rendered.get("observe_mode") == Some(&Value::Bool(true)),
        workspace: envelope.source.cwd.clone(),
        session_id: payload_value(&["session_id", "sessionId"]),
        tool_call_id: payload_value(&["tool_call_id", "toolCallId", "tool_use_id"]),
        guard_home: envelope.source.guard_home.clone(),
        home: envelope.source.home_dir.clone(),
        sink_command: sink_command.to_vec(),
    }
}

/// The first of `names` the payload holds, as a chained `get` reads it.
fn first<'a>(payload: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| payload.get(*name))
}

#[cfg(all(test, unix))]
#[path = "edge_containment_tests.rs"]
mod tests;
