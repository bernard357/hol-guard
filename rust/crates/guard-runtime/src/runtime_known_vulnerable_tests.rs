use super::*;
use crate::policy_enforcement::validate_pre_tool_result_matrix;
use guard_contracts::{PreToolActionV1, PreToolOperationV1, PRE_TOOL_ACTION_V1_SCHEMA};
use serde_json::json;

fn result(minimum_action: &str) -> PreToolResultV1 {
    PreToolResultV1 {
        schema: "guard-pre-tool-result.v1".into(),
        version: 1,
        authority: "rust".into(),
        action: PreToolActionV1 {
            schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
            version: 1,
            harness: "claude-code".into(),
            event: "PreToolUse".into(),
            action_type: PreToolActionTypeV1::Command,
            operation: PreToolOperationV1::Execute,
            bounded: true,
            sensitive_target: false,
        },
        decision: if matches!(minimum_action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .into(),
        policy_action: minimum_action.into(),
        minimum_action: minimum_action.into(),
        reason_code: "native_test".into(),
        reason: "native test".into(),
        explicitly_benign: minimum_action == "allow",
        command_extensions: None,
        prompt_risk_classes: Vec::new(),
    }
}

fn rule(id: &str, severity: &str, fixed: &str) -> Value {
    json!({
        "advisory_id": id,
        "family": "node",
        "vendor": "nodejs.org",
        "version_scheme": "semver",
        "ranges": [{"introduced": "20.0.0", "fixed": fixed, "last_affected": null}],
        "platforms": [{"os": "*", "arch": "*"}],
        "severity": severity,
        "known_exploited": false,
    })
}

fn advisories(rules: Value, state: &str) -> LaunchAdvisories {
    let mut source = json!({"state": state, "anchored": true});
    if state == "stale" {
        source["reason"] = json!("bundle_expired");
        source["expired_at"] = json!(1_792_584_000.0);
    }
    LaunchAdvisories::for_tests(rules, source)
}

fn node(version: &str) -> Value {
    json!({
        "artifact_id": "launch",
        "family": "node",
        "vendor": "nodejs.org",
        "version": version,
        "build_id": null,
        "os": "linux",
        "arch": "x64",
        "executable_sha256": "a".repeat(64),
        "component_identity_sha256": null,
        "identity_assurance": "locally_trusted",
    })
}

fn finding(version: &str, rules: Value) -> Option<Finding> {
    affected_artifact(
        "/opt/node/bin/node".into(),
        &node(version),
        &advisories(rules, "verified"),
    )
}

#[test]
fn a_known_affected_build_is_held_for_review_with_both_choices() {
    let found = finding("22.1.0", json!([rule("CVE-1", "high", "22.5.0")])).unwrap();
    let raised = raise(result("allow"), &found, "require-reapproval", false);
    validate_pre_tool_result_matrix(&raised).unwrap();
    assert_eq!(raised.minimum_action, "require-reapproval");
    assert_eq!(raised.reason_code, FINDING);
    assert!(is_review_finding(&raised.reason_code));
    assert!(!raised.explicitly_benign);
    assert!(raised.reason.contains("CVE-1"));
    assert!(raised.reason.contains("not bound to the started process"));
}

#[test]
fn patched_unknown_and_low_severity_builds_stay_quiet() {
    let rules = json!([rule("CVE-1", "high", "22.5.0")]);
    assert_eq!(finding("22.5.0", rules.clone()), None);
    assert_eq!(finding("22.9.1", rules.clone()), None);
    assert_eq!(finding("unknown", rules.clone()), None);
    assert_eq!(
        finding("22.1.0", json!([rule("CVE-2", "medium", "22.5.0")])),
        None
    );
    let mut spoofed = node("22.1.0");
    spoofed["identity_assurance"] = json!("self_reported");
    spoofed["executable_sha256"] = Value::Null;
    let report =
        crate::runtime_identity::assess_launch(&spoofed, &advisories(rules, "verified")).unwrap();
    assert_ne!(
        report["artifacts"][0]["identity_assurance"],
        "locally_trusted"
    );
}

#[test]
fn the_strongest_advisory_names_the_finding() {
    let found = finding(
        "22.1.0",
        json!([
            rule("CVE-HIGH", "high", "22.5.0"),
            rule("CVE-CRIT", "critical", "22.4.0"),
        ]),
    )
    .unwrap();
    assert_eq!(found.advisory_id, "CVE-CRIT");
    assert_eq!(found.severity, "critical");
}

#[test]
fn a_stale_bundle_still_reports_what_it_matched() {
    let stale = advisories(json!([rule("CVE-1", "high", "22.5.0")]), "stale");
    let found = affected_artifact("/opt/node/bin/node".into(), &node("22.1.0"), &stale).unwrap();
    assert_eq!(found.expired_at, Some(1_792_584_000.0));
    assert!(found.describe().contains("past its expiry"));
}

#[test]
fn watch_records_the_would_be_review_and_lets_the_launch_run() {
    let found = finding("22.1.0", json!([rule("CVE-1", "high", "22.5.0")])).unwrap();
    let observed = raise(result("allow"), &found, "require-reapproval", true);
    validate_pre_tool_result_matrix(&observed).unwrap();
    assert_eq!(observed.minimum_action, "warn");
    assert_eq!(observed.decision, "allow");
    assert_eq!(observed.reason_code, OBSERVED);
    assert!(!is_review_finding(&observed.reason_code));
    assert!(observed
        .reason
        .contains("would have required require-reapproval"));
    let warned = raise(result("allow"), &found, "warn", false);
    assert_eq!(warned.minimum_action, "warn");
    assert!(!warned.reason.contains("would have"));
}

#[test]
fn strict_blocks_and_a_stronger_result_keeps_its_own_reason() {
    let found = finding("22.1.0", json!([rule("CVE-1", "critical", "22.5.0")])).unwrap();
    for start in [
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
    ] {
        let raised = raise(result(start), &found, "block", false);
        validate_pre_tool_result_matrix(&raised).unwrap();
        assert_eq!(raised.minimum_action, "block");
        assert_eq!(raised.reason_code, FINDING);
    }
    let kept = raise(result("block"), &found, "require-reapproval", false);
    assert_eq!(kept.reason_code, "native_test");
    let held = raise(
        result("require-reapproval"),
        &found,
        "require-reapproval",
        false,
    );
    assert_eq!(held.reason_code, FINDING);
}

#[cfg(unix)]
fn executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn launches_resolve_the_way_the_shell_would() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    let local = root.path().join("tools");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&local).unwrap();
    executable(&bin.join("node"));
    executable(&local.join("node"));
    let search = bin.to_string_lossy().into_owned();
    let launches = |command: &str| {
        let mut found = runtime_launches(command, Some(root.path()), root.path(), Some(&search))
            .into_iter()
            .map(|path| path.strip_prefix(root.path()).unwrap().to_owned())
            .collect::<Vec<_>>();
        found.sort();
        found
    };
    assert_eq!(launches("node server.js"), [Path::new("bin/node")]);
    assert_eq!(
        launches("cd x && ./tools/node a.js"),
        [Path::new("tools/node")]
    );
    assert_eq!(
        launches("bash -c 'node a.js' && tools/node b.js"),
        [Path::new("bin/node"), Path::new("tools/node")]
    );
    assert!(launches("PATH=/elsewhere node a.js").is_empty());
    assert!(launches("npm test && python3 -V && echo node").is_empty());
}

#[test]
fn runtime_names_cover_node_and_its_windows_spelling_only() {
    assert!(is_runtime_name("node"));
    assert!(is_runtime_name("/usr/bin/nodejs"));
    assert!(is_runtime_name("C:/Program Files/nodejs/NODE.EXE"));
    assert!(!is_runtime_name("node-gyp"));
    assert!(!is_runtime_name("deno"));
}

#[test]
fn only_command_text_is_read() {
    let string = json!({"tool_input": {"command": "node a.js"}});
    assert_eq!(command_text(&string).as_deref(), Some("node a.js"));
    let argv = json!({"tool_input": {"command": ["bash", "-lc", "node a.js"]}});
    assert_eq!(command_text(&argv).as_deref(), Some("node a.js"));
    assert_eq!(
        command_text(&json!({"tool_input": {"command": "  "}})),
        None
    );
    assert_eq!(command_text(&json!({"tool_input": {"url": "x"}})), None);
}
