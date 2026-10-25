use std::fs;
use std::path::Path;

use serde_json::Value;

use super::*;

// The values are split so repository secret scanners do not read this file as
// holding a credential; they are joined into the planted fixtures below.
fn github_token() -> String {
    ["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz", "012345"].concat()
}

fn aws_key() -> String {
    ["AKIA", "IOSFODNN7", "REALKEY"].concat()
}

fn request(root: &Path) -> SnapshotRequest {
    SnapshotRequest {
        root: root.to_str().unwrap().to_owned(),
        mode: SnapshotMode::Content,
        max_entries: 0,
        max_total_bytes: 0,
        max_file_bytes: 0,
        max_visited_entries: 0,
        secrets: true,
    }
}

fn scan(root: &Path) -> Value {
    snapshot(&request(root)).unwrap()
}

fn secrets(result: &Value) -> &Value {
    &result["secrets"]
}

fn findings(result: &Value) -> &Vec<Value> {
    secrets(result)["findings"].as_array().unwrap()
}

fn planted() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("src/deploy.py"),
        format!("import os\nGH_TOKEN = {}\n", github_token()),
    )
    .unwrap();
    fs::write(
        dir.path().join("settings.yaml"),
        format!("name: app\naws_access_key_id: {}\n", aws_key()),
    )
    .unwrap();
    dir
}

#[test]
fn planted_secrets_are_found_with_rule_path_line_and_fingerprint() {
    let dir = planted();
    let result = scan(dir.path());
    let found = findings(&result);
    let github = found
        .iter()
        .find(|item| item["rule_id"] == "github-token")
        .expect("github token finding");
    assert_eq!(github["path"], "src/deploy.py");
    assert_eq!(github["line"], 2);
    assert_eq!(github["fingerprint"].as_str().unwrap().len(), 32);
    assert!(github["severity"].is_string());
    let aws = found
        .iter()
        .find(|item| item["rule_id"] == "aws-access-key")
        .expect("aws key finding");
    assert_eq!(
        (aws["path"].as_str(), aws["line"].as_u64()),
        (Some("settings.yaml"), Some(2))
    );
    assert_eq!(secrets(&result)["status"], "complete");
    assert_eq!(secrets(&result)["files_scanned"], 2);
}

#[test]
fn no_secret_value_or_fragment_reaches_the_serialized_result() {
    let dir = planted();
    let result = scan(dir.path());
    let text = serde_json::to_string(&result).unwrap();
    for value in [github_token(), aws_key()] {
        assert!(!text.contains(&value));
        // No reversible fragment: neither half of the value is present.
        let middle = value.len() / 2;
        assert!(!text.contains(&value[..middle]));
        assert!(!text.contains(&value[middle..]));
    }
    for finding in findings(&result) {
        let keys: Vec<&str> = finding
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "confidence",
                "family",
                "fingerprint",
                "line",
                "path",
                "rule_id",
                "severity"
            ]
            .into_iter()
            .collect()
        );
    }
}

#[test]
fn fingerprints_are_stable_per_secret_and_distinct_between_secrets() {
    let dir = planted();
    let first = scan(dir.path());
    let second = scan(dir.path());
    assert_eq!(findings(&first), findings(&second));
    let fingerprints: std::collections::BTreeSet<&str> = findings(&first)
        .iter()
        .map(|item| item["fingerprint"].as_str().unwrap())
        .collect();
    assert_eq!(fingerprints.len(), findings(&first).len());
    // The same value moved to another line keeps its fingerprint.
    fs::write(
        dir.path().join("src/deploy.py"),
        format!("import os\n\n\nGH_TOKEN = {}\n", github_token()),
    )
    .unwrap();
    let moved = scan(dir.path());
    let before = findings(&first)
        .iter()
        .find(|item| item["rule_id"] == "github-token")
        .unwrap();
    let after = findings(&moved)
        .iter()
        .find(|item| item["rule_id"] == "github-token")
        .unwrap();
    assert_eq!(before["fingerprint"], after["fingerprint"]);
    assert_eq!(after["line"], 4);
}

#[test]
fn fingerprints_differ_between_repositories() {
    let one = SecretScan::new("one");
    let other = SecretScan::new("other");
    assert_ne!(one.fingerprint_key, other.fingerprint_key);
}

#[test]
fn benign_content_yields_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("ids.json", "{\"request_id\": \"3f2504e0-4f89-41d3-9a0c-0305e82c3301\"}\n"),
        (
            "package-lock.json",
            "{\"integrity\": \"sha512-Zq0m3sT8kQeWw1Hn5y9bQ2sXk7mVdP4aLr6uYc0tJf1gN8oRhEiBvDxUaCwMlK2Zp3y5q9A==\"}\n",
        ),
        ("yarn.lock", "resolved \"https://registry.example.test/a/-/a-1.0.0.tgz#da39a3ee5e6b4b0d3255bfef95601890afd80709\"\n"),
        ("config.example.env", "API_KEY=YOUR_API_KEY\nSECRET_TOKEN=changeme\n"),
        ("README.md", "Set `API_KEY` to YOUR_API_KEY before running.\n"),
        (
            "tests/auth.test.js",
            "describe('auth', () => { it('rejects', () => { expect(login({ password: 'fake-password-value' })).toBe(false); }); });\n",
        ),
        ("src/main.rs", "fn main() {\n    let token = std::env::var(\"API_TOKEN\");\n}\n"),
    ];
    for (name, body) in cases {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }
    let result = scan(dir.path());
    assert!(
        findings(&result).is_empty(),
        "benign fixtures reported: {:?}",
        findings(&result)
    );
    assert_eq!(secrets(&result)["status"], "complete");
}

#[test]
fn credential_stores_are_skipped_and_counted_never_reported() {
    let dir = tempfile::tempdir().unwrap();
    let line = format!("GH_TOKEN = {}\n", github_token());
    for name in [
        ".env",
        ".env.staging",
        "server.pem",
        "deploy.KEY",
        "bundle.p12",
        ".npmrc",
        ".aws/credentials",
        "id_rsa",
        "terraform.tfvars",
    ] {
        let path = dir.path().join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &line).unwrap();
    }
    fs::write(dir.path().join("plain.py"), "print('ok')\n").unwrap();
    let result = scan(dir.path());
    assert!(findings(&result).is_empty());
    assert_eq!(secrets(&result)["skipped"]["credential_store"], 9);
    assert_eq!(secrets(&result)["files_scanned"], 1);
    assert_eq!(secrets(&result)["status"], "complete");
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains(&github_token()));
}

#[test]
fn binary_and_non_utf8_files_are_counted_as_not_text() {
    let dir = planted();
    fs::write(dir.path().join("logo.png"), github_token()).unwrap();
    fs::write(dir.path().join("blob.dat"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
    let result = scan(dir.path());
    assert_eq!(secrets(&result)["skipped"]["not_text"], 2);
    assert_eq!(findings(&result).len(), 2);
}

#[test]
fn snapshot_limits_leave_the_scan_incomplete() {
    let dir = planted();
    let mut capped = request(dir.path());
    capped.max_entries = 1;
    let result = snapshot(&capped).unwrap();
    assert_eq!(secrets(&result)["status"], "incomplete");
    assert_eq!(secrets(&result)["truncation_reasons"][0], "entry_cap");
}

#[test]
fn the_finding_cap_leaves_the_scan_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let body: String = (0..MAX_SECRET_FINDINGS + 100)
        .map(|index| format!("GH_TOKEN_{index} = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz{index:06}\n"))
        .collect();
    fs::write(dir.path().join("many.py"), body).unwrap();
    let result = scan(dir.path());
    assert_eq!(findings(&result).len(), MAX_SECRET_FINDINGS);
    assert_eq!(secrets(&result)["status"], "incomplete");
    assert_eq!(secrets(&result)["truncation_reasons"][0], "max_findings");
}

#[cfg(unix)]
#[test]
fn a_symlink_never_leads_the_scan_outside_the_root() {
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("leak.py"),
        format!("T = {}\n", github_token()),
    )
    .unwrap();
    fs::create_dir_all(outside.path().join("dir")).unwrap();
    fs::write(
        outside.path().join("dir/leak.py"),
        format!("T = {}\n", github_token()),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("ok.py"), "x = 1\n").unwrap();
    std::os::unix::fs::symlink(outside.path().join("leak.py"), dir.path().join("link.py")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("dir"), dir.path().join("linked")).unwrap();
    let result = scan(dir.path());
    assert!(findings(&result).is_empty());
    assert_eq!(secrets(&result)["files_scanned"], 1);
}

#[test]
fn policy_directories_are_not_scanned() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("node_modules/dep")).unwrap();
    fs::write(
        dir.path().join("node_modules/dep/index.js"),
        format!("T = {}\n", github_token()),
    )
    .unwrap();
    assert!(findings(&scan(dir.path())).is_empty());
}

#[test]
fn requesting_secrets_does_not_change_the_snapshot_identity() {
    let dir = planted();
    let with = scan(dir.path());
    let mut plain = request(dir.path());
    plain.secrets = false;
    let without = snapshot(&plain).unwrap();
    assert_eq!(with["snapshot_digest"], without["snapshot_digest"]);
    assert_eq!(
        with["input_manifest_digest"],
        without["input_manifest_digest"]
    );
    assert!(without.get("secrets").is_none());
}

#[test]
fn secrets_need_content_mode() {
    let dir = planted();
    let mut stat = request(dir.path());
    stat.mode = SnapshotMode::Stat;
    assert_eq!(
        snapshot(&stat).unwrap_err(),
        "workspace_snapshot_secrets_need_content"
    );
}
