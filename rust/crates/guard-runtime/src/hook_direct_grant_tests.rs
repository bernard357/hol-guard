//! The direct lane's grant step for a grant-routed `PreToolUse`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::{GuardHookLocalCliRulesV1, GuardHookSourceMetadataV2};
use serde_json::{json, Map, Value};

use super::{answer, granted_answer, GrantCall};
use crate::hook_direct::HookDirectDefer;
use crate::local_cli_hook_contained::OUTSIDE_ROOTS_REASON;
use crate::local_cli_hook_op::tests::Fixture;

const SINK_COMMAND: [&str; 3] = [
    "/opt/hol guard/bin/python",
    "-m",
    "codex_plugin_scanner.cli",
];
const COMMAND: &str = "npm run build";

/// `npm run build` in the fixture's workspace, read with the fixture's rules.
struct Call {
    payload: Map<String, Value>,
    source: GuardHookSourceMetadataV2,
    rules: GuardHookLocalCliRulesV1,
    sink_command: Vec<String>,
}

impl Call {
    fn new(fixture: &Fixture) -> Self {
        let request = fixture.request(COMMAND, "review", true);
        let Value::Object(payload) = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": COMMAND, "description": "Run the build"},
            "cwd": request.cwd,
            "session_id": "sess-1",
            "tool_call_id": "call-1",
        }) else {
            unreachable!("the payload is an object")
        };
        Self {
            payload,
            source: GuardHookSourceMetadataV2 {
                cwd: Some(request.cwd.clone()),
                home_dir: request.home_dir.clone().expect("the fixture names a home"),
                guard_home: request.guard_home.clone(),
                source_ref_external_allowed: false,
                execution_environment: None,
            },
            rules: GuardHookLocalCliRulesV1 {
                store_path: request.store_path.clone(),
                user_home: request.user_home.clone(),
                env: BTreeMap::new(),
                exact_action_control_digest: None,
            },
            sink_command: SINK_COMMAND.map(str::to_owned).to_vec(),
        }
    }

    fn grant_call<'a>(&'a self, harness: &'a str, sink: bool) -> GrantCall<'a> {
        GrantCall {
            harness,
            payload: &self.payload,
            source: &self.source,
            contained: harness == "claude-code",
            sink_command: sink.then_some(self.sink_command.as_slice()),
            deadline: Instant::now() + Duration::from_secs(5),
        }
    }
}

/// The edge's answer for the outside-roots review it routes to `route`.
fn edge(route: &str) -> Value {
    json!({
        "event_name": "PreToolUse",
        "containment_route": route,
        "result": {
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
        },
        "harness_response": {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "review",
            },
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

/// Before this step the direct lane paused a review the user's grant covers
/// for approval, where the daemon runs it in the widened sandbox.
#[test]
fn a_granted_review_is_routed_to_the_sink_instead_of_paused() {
    let fixture = Fixture::new("direct-grant-routed");
    allowed(&fixture);
    let call = Call::new(&fixture);

    let Ok(Some((answered, snapshot))) = granted_answer(
        edge("grant"),
        &call.grant_call("claude-code", true),
        &call.rules,
    ) else {
        panic!("a granted review is answered");
    };

    // The review stays the edge's; only the harness response changes.
    assert_eq!(answered["result"]["minimum_action"], "review");
    let response = &answered["harness_response"];
    assert_eq!(response["reason_code"], "native_contained_execution_routed");
    assert_eq!(
        response["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
    let command = response["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .expect("command is text");
    let argv = crate::mcp_proxy_shlex::split(command).expect("the sink command is quoted");
    assert_eq!(argv[..3], SINK_COMMAND);
    let request_file = Path::new(argument_after(&argv, "--request-file")).to_owned();
    assert!(request_file.is_file(), "the sink's request is written");
    // An answer that defers after routing leaves nothing behind.
    drop(snapshot.expect("the routed call names its request"));
    assert!(
        !request_file.exists(),
        "the request is removed with the snapshot"
    );
}

#[test]
fn without_an_allowed_grant_the_review_goes_on_to_the_saved_decision() {
    let fixture = Fixture::new("direct-grant-unset");
    let call = Call::new(&fixture);

    let answered = granted_answer(
        edge("grant"),
        &call.grant_call("claude-code", true),
        &call.rules,
    );

    assert!(matches!(answered, Ok(None)));
}

#[test]
fn a_harness_that_cannot_be_rewritten_keeps_its_review() {
    let fixture = Fixture::new("direct-grant-codex");
    allowed(&fixture);
    let call = Call::new(&fixture);

    let answered = granted_answer(edge("grant"), &call.grant_call("codex", false), &call.rules);

    assert!(matches!(answered, Ok(None)));
}

#[test]
fn without_a_bound_sink_a_contained_harness_defers_to_the_daemon() {
    let fixture = Fixture::new("direct-grant-unbound");
    allowed(&fixture);
    let call = Call::new(&fixture);

    let answered = granted_answer(
        edge("grant"),
        &call.grant_call("claude-code", false),
        &call.rules,
    );

    assert!(matches!(
        answered,
        Err(HookDirectDefer::ContainedRouteFailed)
    ));
}

#[test]
fn an_edge_answer_not_routed_to_the_grant_is_left_alone() {
    let fixture = Fixture::new("direct-grant-none");
    allowed(&fixture);
    let call = Call::new(&fixture);
    let bytes = serde_json::to_vec(&edge("none")).expect("edge bytes");

    let answered = answer(&bytes, &call.grant_call("claude-code", true));

    assert!(matches!(answered, Ok(None)));
}
