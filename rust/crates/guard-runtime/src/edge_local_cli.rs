//! The daemon's custom extension rules, settled in the edge answer.
//!
//! The daemon sends where its rules live and the home and environment a
//! command's launch resolves against; the edge reads the rule for a
//! `PreToolUse` and returns the response the rule leaves, so the daemon no
//! longer asks for it in a second request.
//!
//! An allowed call is checked only while some custom block rule exists: its
//! grant can block it, and a launch or grant the edge cannot check blocks it
//! as unverified. A review is checked outside Watch: a block applies to any
//! review, and an allow lifts only an overridable review due to
//! non-recognition alone. A rule the edge cannot read leaves the review
//! standing. The daemon still applies each answer where it did before:
//! a granted containment answers an allowed call first, and a saved
//! exact-action block wins over a custom allow.

use std::path::Path;
use std::time::Duration;

use guard_contracts::{GuardHookEnvelopeV2, GuardHookLocalCliRuleV1, HookLocalCliRuleRequestV1};
use serde_json::{json, Map, Value};

use crate::hook_direct::local_cli::block;
use crate::hook_direct::local_cli::rule_op::{self, RuleVerdict};

/// How long the check waits for a writer's exclusive storage hold.
const STORAGE_GATE_WAIT: Duration = Duration::from_secs(2);
const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];

/// The custom extension rule the daemon asked for, or `None` when it asked
/// for none or none applies. `Err` only when the response cannot be rendered.
pub(super) fn settle(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    result: &Value,
) -> Result<Option<GuardHookLocalCliRuleV1>, String> {
    let (Some(rules), "PreToolUse", Some(result)) = (
        envelope.local_cli_rules.as_ref(),
        event_name,
        result.as_object(),
    ) else {
        return Ok(None);
    };
    let text = |key: &str| result.get(key).and_then(Value::as_str);
    let recording_only = envelope.recording_only;
    let response = if text("minimum_action") == Some("allow") {
        // Watch records only a call the edge fully allowed.
        if (recording_only && text("decision") != Some("allow"))
            || !crate::local_cli_hook_contained::has_block_rules_at(
                &rules.store_path,
                &envelope.source.guard_home,
            )
        {
            return Ok(None);
        }
        let verdict = checked(envelope, result, "allowed").unwrap_or(RuleVerdict::Unverified);
        match verdict {
            RuleVerdict::Blocked(name) => {
                block::block_response(harness, result, &name, recording_only)
            }
            RuleVerdict::Unverified => block::unverified_response(harness, result, recording_only),
            RuleVerdict::None | RuleVerdict::Allowed => return Ok(None),
        }
        .map(|response| (true, response))
    } else if !recording_only
        && text("minimum_action").is_some_and(|action| REVIEW_ACTIONS.contains(&action))
    {
        match checked(envelope, result, "review") {
            Some(RuleVerdict::Blocked(name)) => {
                block::block_response(harness, result, &name, false)
                    .map(|response| (true, response))
            }
            Some(RuleVerdict::Allowed) => {
                let mut allowed = result.clone();
                for key in ["decision", "minimum_action", "policy_action"] {
                    allowed.insert(key.to_owned(), json!("allow"));
                }
                crate::hook_direct::saved_decision::render(harness, &allowed, "accepted")
                    .map(|response| (false, response))
            }
            _ => return Ok(None),
        }
    } else {
        return Ok(None);
    };
    let (blocked, harness_response) =
        response.ok_or_else(|| "native_hook_edge_response_invalid".to_owned())?;
    Ok(Some(GuardHookLocalCliRuleV1 {
        blocked,
        harness_response,
    }))
}

/// The rule's verdict under the shared storage hold, or `None` when the hold
/// cannot be taken.
fn checked(
    envelope: &GuardHookEnvelopeV2,
    result: &Map<String, Value>,
    mode: &str,
) -> Option<RuleVerdict> {
    let rules = envelope.local_cli_rules.as_ref()?;
    let request = HookLocalCliRuleRequestV1 {
        schema: guard_contracts::HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA.to_owned(),
        request_id: "edge-local-cli-rule".to_owned(),
        store_path: rules.store_path.clone(),
        guard_home: envelope.source.guard_home.clone(),
        mode: mode.to_owned(),
        payload: envelope
            .raw_payload
            .as_object()
            .cloned()
            .unwrap_or_default(),
        native_result: result.clone(),
        workspace: envelope.source.cwd.clone(),
        home_dir: envelope.source.home_dir.clone(),
        user_home: Some(rules.user_home.clone()),
        env: Some(rules.env.clone()),
    };
    let _hold = crate::hook_evidence_store_gate::hold_storage_gate(
        Path::new(&envelope.source.guard_home),
        STORAGE_GATE_WAIT,
    )
    .ok()?;
    Some(match mode {
        "allowed" => rule_op::allowed_verdict(&request),
        _ => rule_op::review_verdict(&request),
    })
}

#[cfg(test)]
#[path = "edge_local_cli_tests.rs"]
mod tests;
