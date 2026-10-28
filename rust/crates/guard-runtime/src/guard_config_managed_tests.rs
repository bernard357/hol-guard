//! Managed-policy composition: a managed requirement only ever strengthens
//! the local configuration it is composed into.

use super::{apply_managed_policy, ManagedInput};
use serde_json::{json, Map, Value};

fn policy(settings: Value, locked: &[&str]) -> ManagedInput {
    ManagedInput {
        settings: object(settings),
        locked_settings: locked.iter().map(|path| (*path).to_owned()).collect(),
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("expected an object, got {other}"),
    }
}

fn compose(local: Value, policy: &ManagedInput) -> Value {
    Value::Object(apply_managed_policy(&object(local), policy))
}

#[test]
fn locked_values_override_local_and_actions_only_strengthen() {
    let policy = policy(
        json!({"mode": "enforce", "actions": {"shell": "block", "read": "warn"}}),
        &["mode"],
    );
    let composed = compose(
        json!({"mode": "monitor", "actions": {"shell": "allow", "read": "block", "write": "review"}}),
        &policy,
    );
    assert_eq!(
        composed,
        json!({"mode": "enforce", "actions": {"shell": "block", "read": "block", "write": "review"}})
    );
}

#[test]
fn managed_value_replaces_invalid_local_type() {
    let policy = policy(json!({"mode": "enforce"}), &["mode"]);
    assert_eq!(compose(json!({"mode": true}), &policy)["mode"], "enforce");
}

#[test]
fn partial_managed_nested_policy_preserves_local_strengthening() {
    let policy = policy(
        json!({"risk_actions": {"network_egress": "block"}}),
        &["risk_actions.network_egress"],
    );
    let composed = compose(
        json!({"risk_actions": {"network_egress": "review", "credential_access": "block"}}),
        &policy,
    );
    assert_eq!(
        composed["risk_actions"],
        json!({"network_egress": "block", "credential_access": "block"})
    );
}

#[test]
fn local_policy_can_strengthen_locked_action() {
    let policy = policy(json!({"default_action": "warn"}), &["default_action"]);
    let composed = compose(json!({"default_action": "block"}), &policy);
    assert_eq!(composed["default_action"], "block");
}

#[test]
fn managed_mode_lock_overrides_watch_payload() {
    let policy = policy(json!({"mode": "enforce"}), &["mode"]);
    let composed = compose(
        json!({"mode": "observe", "protection_posture": "watch", "security_level": "balanced"}),
        &policy,
    );
    assert_eq!(composed["mode"], "enforce");
}

#[test]
fn local_stronger_mode_survives_a_weaker_managed_mode() {
    let policy = policy(json!({"mode": "prompt"}), &["mode"]);
    assert_eq!(
        compose(json!({"mode": "enforce"}), &policy)["mode"],
        "enforce"
    );
}

#[test]
fn managed_watch_auto_revert_lock_keeps_hours() {
    let policy = policy(
        json!({"watch_auto_revert_hours": 24}),
        &["watch_auto_revert_hours"],
    );
    let composed = compose(json!({"watch_auto_revert_hours": 0}), &policy);
    assert_eq!(composed["watch_auto_revert_hours"], 24);
}
