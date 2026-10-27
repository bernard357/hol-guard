//! The `hol-guard hook` command reads a daemon answer as the Python
//! `emit_hook_review` did. The vectors hold what `_daemon_response_to_native`
//! printed for a bridge-rendered harness and the policy action its exit
//! status followed for every other one.

use std::path::Path;

use serde_json::Value;

use super::cli_hook_emit_document;

const VECTORS: &str = include_str!("../testdata/hook_cli_emit/vectors.json");

fn field<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key].as_str().expect("vector field")
}

#[test]
fn every_vector_reads_as_python_read_it() {
    let cases: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = cases.as_array().expect("cases");
    assert!(cases.len() >= 20, "vector set shrank");
    for case in cases {
        let document = cli_hook_emit_document(
            field(case, "harness"),
            field(case, "event_name"),
            field(case, "response"),
            None,
        )
        .unwrap_or_else(|| panic!("no document for {case}"));
        if let Some(action) = case.get("policy_action") {
            assert_eq!(document.get("policy_action"), Some(action), "{case}");
            assert_eq!(document.len(), 1, "{case}");
            continue;
        }
        for key in ["stdout", "stderr", "exit_code"] {
            assert_eq!(document.get(key), case.get(key), "{key} for {case}");
        }
    }
}

#[test]
fn a_lone_surrogate_reason_prints_as_its_escape() {
    let document = cli_hook_emit_document(
        "kimi",
        "PreToolUse",
        r#"{"policy_action":"block","reason":"x\ud800"}"#,
        None,
    )
    .expect("document");
    assert_eq!(document["exit_code"], 2);
    assert_eq!(document["stderr"], "x\\ud800");
    assert!(document["stdout"]
        .as_str()
        .expect("stdout")
        .contains(r#""permissionDecisionReason":"x\ud800""#));
}

#[test]
fn an_unreadable_answer_has_no_document() {
    for (harness, text) in [
        ("kimi", "[]"),
        ("codex", "not json"),
        // Python would print a list reason through `repr`; the caller fails
        // closed instead of guessing that text.
        ("kimi", r#"{"policy_action":"block","reason":["a"]}"#),
    ] {
        assert!(
            cli_hook_emit_document(harness, "PreToolUse", text, None).is_none(),
            "{harness} {text}"
        );
    }
}

#[test]
fn grok_reads_an_empty_answer_by_event() {
    for (event, exit_code) in [
        ("SessionStart", 0),
        ("UserPromptSubmit", 0),
        ("PreToolUse", 2),
    ] {
        let document = cli_hook_emit_document("grok", event, "{}", None).expect("document");
        assert_eq!(document["exit_code"], exit_code, "{event}");
    }
}

#[test]
fn an_authority_block_names_the_store_the_command_reads() {
    // The printer reads the daemon's answer for a `hol-guard hook` call that
    // named a store of its own. A person who pastes the bare command into a
    // shell repairs the default install while this one stays blocked, so the
    // recovery line has to carry the store back out.
    let reason =
        r#"{"policy_action":"block","reason":"blocked by the native command extension policy"}"#;
    let named = cli_hook_emit_document(
        "zcode",
        "PreToolUse",
        reason,
        Some(Path::new("/synthetic/guards/ci")),
    )
    .expect("document");
    let printed = format!(
        "{}{}",
        named["stdout"].as_str().expect("stdout"),
        named["stderr"].as_str().expect("stderr")
    );
    assert!(
        printed.contains("command --guard-home /synthetic/guards/ci controls recover-authority"),
        "{printed}"
    );

    let unnamed = cli_hook_emit_document("zcode", "PreToolUse", reason, None).expect("document");
    let printed = format!(
        "{}{}",
        unnamed["stdout"].as_str().expect("stdout"),
        unnamed["stderr"].as_str().expect("stderr")
    );
    assert!(
        printed.contains("Run `hol-guard command controls recover-authority`"),
        "{printed}"
    );
    assert!(!printed.contains("--guard-home"), "{printed}");
}
