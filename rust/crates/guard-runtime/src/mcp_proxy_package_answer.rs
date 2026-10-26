//! The answer a stopped MCP proxy call gives, for the `package_answer` check.
//!
//! The proxy decides a package-lane call through `package_precheck`,
//! `package_compose` and `package_postclaim`; each of those names the kind of
//! stop (a stored or terminal tool block, a stored or terminal package block,
//! a queued package request). This module writes what that stop says: the
//! agent's message, the error payload, the event label and the receipt
//! signals. The proxy only records the receipt, queues the approval row and
//! frames the JSON-RPC error with what it is given.
//!
//! The relay (`mcp_relay_decide*.rs`) answers the same stops without the
//! proxy, so the text, the queued evaluation and the package decision live
//! here once and the relay modules call them.

use guard_command::decisions::{decision_from_legacy_policy_action, parse_signals};
use guard_contracts::{
    GuardAction, McpPackageAnswerKindV1, McpPackageAnswerQueryV1, McpPackageReasonSignalsQueryV1,
};
use serde_json::{json, Map, Value};

use crate::blocked_request_mode::safe_alternative_reason;

/// A `package_answer` query the resident cannot render: a terminal kind with
/// a permitted action, or a package kind without its evaluation.
pub(crate) const PACKAGE_ANSWER_INVALID: &str = "native_mcp_proxy_package_answer_invalid";

/// `block_tool_call(decision_source="policy-block")`, which every stopped call
/// records under.
const BLOCK_SOURCE: &str = "policy-block";

/// The `terminal_tool` message: a blocked call, or one whose sandbox this
/// runtime cannot provide.
pub(crate) fn terminal_tool_message(tool: &str, server: &str, policy_action: &str) -> String {
    if policy_action == "block" {
        format!("HOL Guard blocked tool call {tool} from {server}.")
    } else {
        format!(
            "HOL Guard requires an enforceable sandbox for tool call {tool} from {server}; this \
             runtime cannot provide one."
        )
    }
}

/// The `stored_tool_block` message: the exact call is already blocked by
/// saved policy, named as a package tool call when it carried a package
/// request.
pub(crate) fn stored_tool_block_message(tool: &str, server: &str, package_request: bool) -> String {
    let kind = if package_request {
        "package tool call"
    } else {
        "tool call"
    };
    format!(
        "HOL Guard blocked {kind} {tool} from {server}. This exact request is already blocked by \
         authenticated saved policy."
    )
}

/// The `terminal_package` message: a blocked package request, or one whose
/// sandbox this runtime cannot provide.
pub(crate) fn terminal_package_message(tool: &str, server: &str, policy_action: &str) -> String {
    if policy_action == "block" {
        format!("HOL Guard blocked package install request {tool} from {server}.")
    } else {
        format!(
            "HOL Guard requires an enforceable sandbox for package install request {tool} from \
             {server}; this runtime cannot provide one."
        )
    }
}

/// The `stored_package_block` message: the exact request is already blocked
/// by stored policy.
pub(crate) fn stored_package_block_message(tool: &str, server: &str) -> String {
    format!(
        "HOL Guard blocked package install request {tool} from {server}. This exact request is \
         already blocked by stored policy with authenticated local integrity."
    )
}

/// The message and data of `_queue_approval_center_response`'s
/// safe-alternative block.
pub(crate) fn safe_alternative_block(
    tool: &str,
    server: &str,
    signals: &[String],
) -> (String, Value) {
    let reason = format!(
        "HOL Guard blocked tool call {tool} from {server}. {}",
        signals.join(" ")
    );
    (
        safe_alternative_reason(&reason, None, None),
        json!({
            "approvalRequests": [],
            "guardPolicyAction": "block",
            "transportOutcome": "not-forwarded",
        }),
    )
}

/// The reason signals of an evaluation: each reason's message, its code when
/// it carries no message, and an empty string when it carries neither, in the
/// order the evaluation reported them.
pub(crate) fn reason_signals(evaluation: &Map<String, Value>) -> Vec<String> {
    evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(|reasons| {
            reasons
                .iter()
                .map(|reason| {
                    reason
                        .get("message")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .or_else(|| reason.get("code").and_then(Value::as_str))
                        .unwrap_or("")
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The evaluation's own risk summary, or an empty string.
fn risk_summary(evaluation: &Map<String, Value>) -> String {
    evaluation
        .get("risk_summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The evaluation a request queued under `safe-alternative` is answered with:
/// the one the lane settled on, restated as the block the agent was actually
/// given, with the guidance text as its own next step.
pub(crate) fn blocked_package_evaluation(evaluation: &Map<String, Value>, message: &str) -> Value {
    let mut blocked = evaluation.clone();
    blocked.insert("decision".to_owned(), json!("block"));
    blocked.insert("policy_action".to_owned(), json!("block"));
    let mut user_copy = blocked
        .get("user_copy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    user_copy.insert("title".to_owned(), json!("Package request blocked"));
    user_copy.insert(
        "summary".to_owned(),
        evaluation
            .get("risk_summary")
            .cloned()
            .unwrap_or_else(|| json!("")),
    );
    user_copy.insert("dashboard_url".to_owned(), Value::Null);
    user_copy.insert("next_step".to_owned(), json!(message));
    user_copy.insert("harness_message".to_owned(), json!(message));
    blocked.insert("user_copy".to_owned(), Value::Object(user_copy));
    Value::Object(blocked)
}

/// The queued package decision: what the reasons' own V2 signals compose,
/// with the evaluation's user copy written over its text. A reason that is not
/// an object projects no signal.
pub(crate) fn package_decision_v2(
    evaluation: &Map<String, Value>,
    action: GuardAction,
) -> Result<Value, &'static str> {
    let reasons = evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let projected =
        crate::mcp_proxy_signals::reason_signals(&McpPackageReasonSignalsQueryV1 { reasons });
    let signals = parse_signals(&projected["signals"]).map_err(|_| PACKAGE_ANSWER_INVALID)?;
    let mut payload =
        decision_from_legacy_policy_action(action, action.as_str(), &signals).to_value();
    let user_copy = evaluation.get("user_copy").and_then(Value::as_object);
    let copy = |key: &str| {
        user_copy
            .and_then(|copy| copy.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let fields = payload.as_object_mut().ok_or(PACKAGE_ANSWER_INVALID)?;
    fields.insert("user_title".to_owned(), copy("title"));
    fields.insert("user_body".to_owned(), copy("summary"));
    fields.insert("harness_message".to_owned(), copy("harness_message"));
    fields.insert("dashboard_primary_detail".to_owned(), copy("summary"));
    Ok(payload)
}

/// The policy action a terminal kind is rendered for: only a terminal one.
fn terminal_action(query: &McpPackageAnswerQueryV1) -> Result<&str, &'static str> {
    match query.policy_action.as_deref() {
        Some(action @ ("block" | "sandbox-required")) => Ok(action),
        _ => Err(PACKAGE_ANSWER_INVALID),
    }
}

fn evaluation(query: &McpPackageAnswerQueryV1) -> Result<&Map<String, Value>, &'static str> {
    query
        .evaluation
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(PACKAGE_ANSWER_INVALID)
}

/// One block answer. `scanner_evidence_always` says whether the event names
/// its scanner evidence even when there is none, which the package blocks do
/// and the tool blocks do not.
fn block(
    message: String,
    data: Value,
    decision: String,
    policy_action: &str,
    signals: Vec<String>,
    scanner_evidence_always: bool,
) -> Value {
    json!({
        "kind": "block",
        "message": message,
        "data": data,
        "decision": decision,
        "policy_action": policy_action,
        "decision_source": BLOCK_SOURCE,
        "signals": signals,
        "scanner_evidence_always": scanner_evidence_always,
    })
}

/// The `package_answer` check.
pub(crate) fn package_answer(query: &McpPackageAnswerQueryV1) -> Result<Value, &'static str> {
    let (tool, server) = (query.tool_name.as_str(), query.server_name.as_str());
    match query.kind {
        McpPackageAnswerKindV1::StoredToolBlock => Ok(block(
            stored_tool_block_message(tool, server, query.package_request),
            json!({"approvalRequests": [], "guardPolicyAction": "block"}),
            "block-stored-policy".to_owned(),
            "block",
            query.signals.clone(),
            false,
        )),
        McpPackageAnswerKindV1::TerminalTool => {
            let action = terminal_action(query)?;
            Ok(block(
                terminal_tool_message(tool, server, action),
                json!({"approvalRequests": [], "guardPolicyAction": action}),
                format!("terminal-{action}"),
                action,
                query.signals.clone(),
                false,
            ))
        }
        McpPackageAnswerKindV1::StoredPackageBlock => {
            let evaluation = evaluation(query)?;
            Ok(block(
                stored_package_block_message(tool, server),
                json!({
                    "approvalRequests": [],
                    "guardPolicyAction": "block",
                    "supplyChainEvaluation": Value::Object(evaluation.clone()),
                }),
                "package-block-stored".to_owned(),
                "block",
                reason_signals(evaluation),
                true,
            ))
        }
        McpPackageAnswerKindV1::TerminalPackage => {
            let action = terminal_action(query)?;
            let evaluation = evaluation(query)?;
            Ok(block(
                terminal_package_message(tool, server, action),
                json!({
                    "approvalRequests": [],
                    "guardPolicyAction": action,
                    "supplyChainEvaluation": Value::Object(evaluation.clone()),
                }),
                format!("terminal-package-{action}"),
                action,
                reason_signals(evaluation),
                true,
            ))
        }
        McpPackageAnswerKindV1::QueuePackage => {
            let evaluation = evaluation(query)?;
            let action = query
                .policy_action
                .as_deref()
                .and_then(GuardAction::from_canonical)
                .ok_or(PACKAGE_ANSWER_INVALID)?;
            let summary = risk_summary(evaluation);
            let reasons = reason_signals(evaluation);
            let safe_alternative_signals: Vec<String> = std::iter::once(summary.clone())
                .chain(reasons.iter().cloned())
                .collect();
            let (message, _) = safe_alternative_block(tool, server, &safe_alternative_signals);
            Ok(json!({
                "kind": "queue",
                "policy_action": action.as_str(),
                "decision_v2": package_decision_v2(evaluation, action)?,
                "risk_summary": summary,
                "risk_signals": reasons,
                "safe_alternative_signals": safe_alternative_signals,
                "safe_alternative_evaluation": blocked_package_evaluation(evaluation, &message),
            }))
        }
    }
}

#[cfg(test)]
#[path = "mcp_proxy_package_answer_tests.rs"]
mod tests;
