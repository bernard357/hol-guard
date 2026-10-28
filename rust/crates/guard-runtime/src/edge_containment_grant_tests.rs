//! The edge's own answer to a grant-routed `PreToolUse`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_contracts::{
    GuardHookContainmentSinkV1, GuardHookEnvelopeV2, GuardHookLocalCliRulesV1,
    GuardHookSourceMetadataV2, GUARD_HOOK_ENVELOPE_V2_SCHEMA,
};
use serde_json::{json, Value};

use super::{answer, DECLINED, KEPT, ROUTED};
use crate::codex_hook_bridge::contain::discard;
use crate::local_cli_hook_contained::OUTSIDE_ROOTS_REASON;
use crate::local_cli_hook_op::tests::Fixture;

const SINK_COMMAND: [&str; 3] = [
    "/opt/hol guard/bin/python",
    "-m",
    "codex_plugin_scanner.cli",
];
const COMMAND: &str = "npm run build";

/// A grant-routed `PreToolUse` for `npm run build` in the fixture's
/// workspace, asking the edge to answer the grant.
fn envelope(fixture: &Fixture) -> GuardHookEnvelopeV2 {
    let request = fixture.request(COMMAND, "review", true);
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
        request_id: Some("edge-containment-grant".to_owned()),
        harness: "claude-code".to_owned(),
        event: "PreToolUse".to_owned(),
        raw_payload: json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": COMMAND, "description": "Run the build"},
            "cwd": request.cwd,
            "session_id": "sess-1",
            "tool_call_id": "call-1",
        }),
        deadline_budget_ms: Some(1_000),
        policy_generation: 1,
        policy_snapshot: Value::Null,
        source: GuardHookSourceMetadataV2 {
            cwd: Some(request.cwd.clone()),
            home_dir: request.home_dir.clone().expect("the fixture names a home"),
            guard_home: request.guard_home.clone(),
            source_ref_external_allowed: false,
            execution_environment: None,
        },
        recording_only: false,
        local_cli_rules: Some(GuardHookLocalCliRulesV1 {
            store_path: request.store_path.clone(),
            user_home: request.user_home.clone(),
            env: BTreeMap::new(),
            exact_action_control_digest: None,
        }),
        observe_local_cli: false,
        record_receipt: false,
        structured_output_config: None,
        containment_sink: Some(GuardHookContainmentSinkV1 {
            sink_command: SINK_COMMAND.map(str::to_owned).to_vec(),
            grant: true,
        }),
    }
}

/// The outside-roots review the edge routes to the grant.
fn outside_roots() -> Value {
    json!({
        "schema": "guard-pre-tool-result.v1",
        "authority": "rust",
        "decision": "review",
        "minimum_action": "review",
        "policy_action": "review",
        "reason_code": OUTSIDE_ROOTS_REASON,
        "reason": "The program lives outside the sandbox's executable roots.",
        "action": {"action_type": "shell"},
        "command_extensions": {
            "binding": {"uncertainty_count": 0, "observations_digest": "sha256:fixture"},
            "observations": [],
                "permission_observations": [],
        },
    })
}

/// The review the edge rendered before the grant step.
fn review() -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "review",
        },
    })
}

fn allowed(fixture: &Fixture) {
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
}

fn argument_after<'a>(argv: &'a [String], flag: &str) -> &'a str {
    let index = argv
        .iter()
        .position(|token| token == flag)
        .unwrap_or_else(|| panic!("{flag} is passed: {argv:?}"));
    &argv[index + 1]
}

#[test]
fn a_granted_call_comes_back_as_the_routed_allow() {
    let fixture = Fixture::new("edge-grant-routed");
    allowed(&fixture);
    let request = envelope(&fixture);
    let mut response = Some(review());

    let answered = answer(
        &request,
        "claude-code",
        &outside_roots(),
        Instant::now(),
        &mut response,
    );

    assert_eq!(answered, Some(ROUTED));
    let response = response.expect("a response");
    assert_eq!(response["policy_action"], "allow");
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    let output = &response["hookSpecificOutput"];
    assert_eq!(output["permissionDecision"], "allow");
    let command = output["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(argv[..3], SINK_COMMAND);
    assert_eq!(argv[3..5], ["guard", "execute-contained-test"]);
    assert_eq!(
        argument_after(&argv, "--guard-home"),
        request.source.guard_home
    );
    discard(Path::new(argument_after(&argv, "--request-file")));
}

#[test]
fn without_an_allowed_grant_the_review_is_declined_unchanged() {
    let unset = Fixture::new("edge-grant-unset");
    let blocked = Fixture::new("edge-grant-blocked");
    let identity = blocked.identity();
    blocked.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    for fixture in [&unset, &blocked] {
        let mut response = Some(review());

        let answered = answer(
            &envelope(fixture),
            "claude-code",
            &outside_roots(),
            Instant::now(),
            &mut response,
        );

        // The daemon goes straight to the review's pause.
        assert_eq!(answered, Some(DECLINED));
        assert_eq!(response, Some(review()));
    }
}

#[test]
fn a_receipt_only_call_keeps_the_granted_receipt() {
    let fixture = Fixture::new("edge-grant-receipt-only");
    allowed(&fixture);
    let mut request = envelope(&fixture);
    request.raw_payload["guard_containment_receipt_only"] = json!(true);
    let mut response = Some(review());

    let answered = answer(
        &request,
        "claude-code",
        &outside_roots(),
        Instant::now(),
        &mut response,
    );

    assert_eq!(answered, Some(KEPT));
    let receipt = response.expect("the granted receipt");
    assert_eq!(receipt["decision"], "deny");
    assert_eq!(receipt["policy_action"], "sandbox-required");
    assert_eq!(
        receipt["reason_code"],
        "native_workspace_containment_required"
    );
    assert_eq!(
        receipt["required_execution_profile"],
        "workspace-contained-v1"
    );
    assert_eq!(receipt["command_binding_digest"], "sha256:fixture");
    assert_eq!(receipt["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn an_envelope_that_does_not_ask_is_not_answered() {
    let fixture = Fixture::new("edge-grant-unasked");
    allowed(&fixture);
    let mut watched = envelope(&fixture);
    watched.recording_only = true;
    let mut sink_only = envelope(&fixture);
    if let Some(sink) = sink_only.containment_sink.as_mut() {
        sink.grant = false;
    }
    let mut without_sink = envelope(&fixture);
    without_sink.containment_sink = None;
    let mut without_rules = envelope(&fixture);
    without_rules.local_cli_rules = None;
    for request in [watched, sink_only, without_sink, without_rules] {
        let mut response = Some(review());

        let answered = answer(
            &request,
            "claude-code",
            &outside_roots(),
            Instant::now(),
            &mut response,
        );

        // Not answered, so the daemon asks for the grant as before.
        assert_eq!(answered, None);
        assert_eq!(response, Some(review()));
    }
}

#[test]
fn a_grant_step_out_of_time_is_not_answered() {
    let fixture = Fixture::new("edge-grant-late");
    allowed(&fixture);
    let request = envelope(&fixture);
    let mut response = Some(review());
    let long_ago = Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("a minute ago");

    let answered = answer(
        &request,
        "claude-code",
        &outside_roots(),
        long_ago,
        &mut response,
    );

    assert_eq!(answered, None);
    assert_eq!(response, Some(review()));
}

/// The grant step records the launch first, as the daemon's resident call
/// does, so the package script's command catalog exists when the grant is
/// read. Without it the command matched no catalog, and the CLI's grant
/// widened the sandbox for a command the user had blocked.
#[test]
fn a_blocked_command_is_read_against_the_catalog_the_launch_records() {
    let fixture = Fixture::new("edge-grant-command-blocked");
    allowed(&fixture);
    let identity = fixture.identity();
    fixture.command_grant(&identity.cli_id, "build", "block");
    let mut response = Some(review());

    let answered = answer(
        &envelope(&fixture),
        "claude-code",
        &outside_roots(),
        Instant::now(),
        &mut response,
    );

    assert_eq!(answered, Some(DECLINED));
    assert_eq!(response, Some(review()));
    assert!(
        fixture
            .commands(&identity.cli_id)
            .iter()
            .any(|(id, _)| id == "build"),
        "the launch recorded the catalog"
    );
}
