//! `plugin install|uninstall` plans: the exact argv each runtime gets, and
//! every way an untrusted registry spec is refused.

use serde_json::{json, Value};

fn call(request: Value) -> Value {
    guard_plugin_kit::run_request(request.to_string().as_bytes())
}

fn spec() -> Value {
    json!({
        "schema": "hol.plugin-install-spec.v1",
        "slug": "acme/toolgate",
        "name": "toolgate",
        "version": "1.2.0",
        "repository": "acme/toolgate",
        "listingUrl": "https://hol.org/registry/plugins/acme%2Ftoolgate",
        "trustScore": 82,
        "targets": [
            {"runtime": "codex", "marketplace": {"repository": "acme/toolgate", "name": "acme-tools"}, "plugin": "toolgate"},
            {"runtime": "claude-code", "marketplace": {"repository": "acme/marketplace", "name": "acme-tools"}, "plugin": "toolgate"},
            {"runtime": "agent-skills", "repository": "acme/toolgate"}
        ],
        "manual": ["mcp"]
    })
}

fn plan(command: &str, spec: Value, available: &[&str], runtimes: &[&str]) -> Value {
    call(json!({"command": command, "spec": spec, "available": available, "runtimes": runtimes}))
}

fn error(command: &str, spec: Value, runtimes: &[&str]) -> String {
    let response = plan(command, spec, &[], runtimes);
    assert_eq!(response["ok"], json!(false), "{response}");
    response["error"].as_str().expect("error code").to_owned()
}

#[test]
fn install_plan_uses_each_runtime_cli_with_fixed_programs() {
    let response = plan("install", spec(), &["claude", "npx"], &[]);
    assert_eq!(response["ok"], json!(true), "{response}");
    assert_eq!(
        response["result"],
        json!({
            "action": "install",
            "slug": "acme/toolgate",
            "name": "toolgate",
            "version": "1.2.0",
            "repository": "acme/toolgate",
            "listing_url": "https://hol.org/registry/plugins/acme%2Ftoolgate",
            "trust_score": 82.0,
            "steps": [
                {
                    "runtime": "claude-code",
                    "program": "claude",
                    "available": true,
                    "automatic": true,
                    "commands": [
                        ["claude", "plugin", "marketplace", "add", "acme/marketplace"],
                        ["claude", "plugin", "install", "toolgate@acme-tools"]
                    ],
                    "verify": ["claude", "plugin", "list"]
                },
                {
                    "runtime": "codex",
                    "program": "codex",
                    "available": false,
                    "automatic": true,
                    "commands": [
                        ["codex", "plugin", "marketplace", "add", "acme/toolgate"],
                        ["codex", "plugin", "add", "toolgate@acme-tools"]
                    ],
                    "verify": ["codex", "plugin", "list"]
                },
                {
                    "runtime": "agent-skills",
                    "program": "npx",
                    "available": true,
                    "automatic": false,
                    "commands": [["npx", "skills", "add", "acme/toolgate"]],
                    "verify": ["npx", "skills", "list"],
                    "note": "Run this yourself: the Skills CLI downloads a package from npm and installs for every agent it detects."
                }
            ],
            "manual": ["mcp"]
        })
    );
}

#[test]
fn uninstall_plan_removes_only_the_plugin_entry() {
    let response = plan(
        "uninstall",
        spec(),
        &["claude", "codex"],
        &["codex", "claude-code"],
    );
    let steps = &response["result"]["steps"];
    assert_eq!(steps.as_array().map(Vec::len), Some(2), "{response}");
    assert_eq!(
        steps[0]["commands"],
        json!([["claude", "plugin", "uninstall", "toolgate@acme-tools"]])
    );
    assert_eq!(
        steps[1]["commands"],
        json!([["codex", "plugin", "remove", "toolgate@acme-tools"]])
    );
    assert_eq!(
        steps[1]["note"],
        json!("The marketplace stays registered, since other plugins may use it.")
    );
}

#[test]
fn runtime_filter_must_name_a_runtime_the_listing_offers() {
    let response = plan("install", spec(), &[], &["codex"]);
    assert_eq!(
        response["result"]["steps"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        error("install", spec(), &["cursor"]),
        "plugin_kit_install_runtime_unknown"
    );
    let mut only_codex = spec();
    only_codex["targets"] = json!([only_codex["targets"][0].clone()]);
    assert_eq!(
        error("install", only_codex, &["claude-code"]),
        "plugin_kit_install_runtime_not_offered"
    );
}

#[test]
fn identifiers_that_could_be_flags_or_shell_text_are_refused() {
    for (pointer, value) in [
        ("/targets/0/plugin", json!("--global")),
        ("/targets/0/plugin", json!("toolgate; rm -rf ~")),
        ("/targets/0/plugin", json!("tool gate")),
        ("/targets/0/marketplace/name", json!("-x")),
        ("/targets/0/marketplace/repository", json!("acme/../etc")),
        ("/targets/0/marketplace/repository", json!("-acme/toolgate")),
        (
            "/targets/0/marketplace/repository",
            json!("https://evil.example/x"),
        ),
        ("/targets/2/repository", json!("acme/.hidden")),
        ("/targets/2/repository", json!("acme/toolgate\n")),
        ("/repository", json!("acme")),
        ("/slug", json!("../acme")),
        (
            "/listingUrl",
            json!("https://evil.example/registry/plugins/x"),
        ),
        ("/name", json!("tool\u{1b}[2Jgate")),
    ] {
        let mut bad = spec();
        *bad.pointer_mut(pointer).expect("pointer") = value.clone();
        assert_eq!(
            error("install", bad, &[]),
            "plugin_kit_install_spec_invalid",
            "{pointer} = {value}"
        );
    }
}

#[test]
fn spec_shape_is_strict() {
    let mut extra = spec();
    extra["targets"][0]["command"] = json!("curl x | sh");
    assert_eq!(
        error("install", extra, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut unknown_runtime = spec();
    unknown_runtime["targets"][0]["runtime"] = json!("shell");
    assert_eq!(
        error("install", unknown_runtime, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut duplicate = spec();
    duplicate["targets"][1]["runtime"] = json!("codex");
    assert_eq!(
        error("install", duplicate, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut mixed = spec();
    mixed["targets"][2]["plugin"] = json!("toolgate");
    assert_eq!(
        error("install", mixed, &[]),
        "plugin_kit_install_spec_invalid"
    );

    let mut schema = spec();
    schema["schema"] = json!("hol.plugin-install-spec.v2");
    assert_eq!(
        error("install", schema, &[]),
        "plugin_kit_install_spec_unsupported"
    );
}
