use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const CATALOG: &str = "contributions/extensions/command.kubernetes-secrets.json";
const CATALOG_TEXT: &str =
    "{\n  \"id\": \"command.kubernetes-secrets\",\n  \"title\": \"List cluster secrets\"\n}\n";

/// A home with one repository under the build tree, which the location
/// screens accept as an ordinary workspace.
fn fixture() -> (PathBuf, PathBuf) {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "guard-tracked-names-{}-{nonce}",
            std::process::id()
        ));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let project = home.join("project");
    std::fs::create_dir_all(project.join(".git/info")).unwrap();
    (
        std::fs::canonicalize(home).unwrap(),
        std::fs::canonicalize(project).unwrap(),
    )
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A version 2 index at `git_dir` listing `names`, as `git add` writes it.
fn write_index(git_dir: &Path, names: &[&str]) {
    let mut bytes = b"DIRC".to_vec();
    bytes.extend_from_slice(&2_u32.to_be_bytes());
    bytes.extend_from_slice(&(names.len() as u32).to_be_bytes());
    for name in names {
        let entry = (62 + name.len() + 8) & !7;
        let start = bytes.len();
        bytes.resize(start + 60, 0);
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.resize(start + entry, 0);
    }
    std::fs::write(git_dir.join("index"), bytes).unwrap();
}

fn cwd(project: &Path) -> Option<&str> {
    project.to_str()
}

#[test]
fn a_tracked_catalog_named_for_secrets_is_a_document() {
    let (_, project) = fixture();
    let file = project.join(CATALOG);
    write(&file, CATALOG_TEXT);
    write_index(&project.join(".git"), &[CATALOG]);
    assert!(guard_secure_fs::credential_named_path(&file));
    assert!(tracked_document(&file, cwd(&project)));
    assert!(!unproven(&file, cwd(&project)));
}

#[test]
fn an_untracked_file_keeps_its_name_review() {
    let (_, project) = fixture();
    let file = project.join(CATALOG);
    write(&file, CATALOG_TEXT);
    write_index(&project.join(".git"), &["README.md"]);
    assert!(unproven(&file, cwd(&project)));
}

#[test]
fn kubernetes_secret_manifests_keep_review() {
    let (_, project) = fixture();
    let yaml = "deploy/app-secrets.yaml";
    let json = "deploy/app-secrets.json";
    write(
        &project.join(yaml),
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\ndata:\n  mode: cHJvZA==\n",
    );
    write(
        &project.join(json),
        "{\"apiVersion\": \"v1\", \"kind\":\"SealedSecret\", \"spec\": {}}\n",
    );
    write_index(&project.join(".git"), &[json, yaml]);
    assert!(unproven(&project.join(yaml), cwd(&project)));
    assert!(unproven(&project.join(json), cwd(&project)));
    assert!(!secret_object(
        "kind: ConfigMap\ndata:\n  secrets: listed\n"
    ));
    assert!(!secret_object("{\"kind\": \"Deployment\"}"));
}

#[test]
fn a_tracked_file_holding_a_credential_keeps_review() {
    let (_, project) = fixture();
    let name = "config/service-secrets.yaml";
    let header = concat!("-----BEGIN RSA PRIVATE", " KEY-----");
    write(
        &project.join(name),
        &format!("signing: |\n  {header}\n  MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo\n"),
    );
    write_index(&project.join(".git"), &[name]);
    assert!(unproven(&project.join(name), cwd(&project)));
}

#[test]
fn another_repository_beside_the_workspace_is_not_proven() {
    let (home, project) = fixture();
    let other = home.join("other");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    let file = other.join(CATALOG);
    write(&file, CATALOG_TEXT);
    write_index(&other.join(".git"), &[CATALOG]);
    assert!(tracked_document(&file, cwd(&other)));
    assert!(unproven(&file, cwd(&project)));
    assert!(unproven(&file, cwd(&home)));
}

#[test]
fn files_under_git_metadata_are_not_proven() {
    let (_, project) = fixture();
    let name = ".git/info/command.kubernetes-secrets.json";
    write(&project.join(name), CATALOG_TEXT);
    write_index(&project.join(".git"), &[name]);
    assert!(unproven(&project.join(name), cwd(&project)));
}

#[test]
fn a_session_without_a_working_directory_proves_nothing() {
    let (_, project) = fixture();
    let file = project.join(CATALOG);
    write(&file, CATALOG_TEXT);
    write_index(&project.join(".git"), &[CATALOG]);
    assert!(unproven(&file, None));
}

#[cfg(unix)]
#[test]
fn a_linked_worktree_of_the_same_repository_is_proven() {
    let (home, project) = fixture();
    let worktree = home.join("project-feature");
    let admin = project.join(".git/worktrees/project-feature");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(&worktree).unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    let backlink = format!("{}\n", worktree.join(".git").display());
    std::fs::write(admin.join("gitdir"), backlink).unwrap();
    let gitfile = format!("gitdir: {}\n", admin.display());
    std::fs::write(worktree.join(".git"), gitfile).unwrap();
    let file = worktree.join(CATALOG);
    write(&file, CATALOG_TEXT);
    write_index(&admin, &[CATALOG]);
    assert!(!unproven(&file, cwd(&project)));
}

#[cfg(unix)]
const ORDINARY: &str = "contributions/extensions/command.kubectl-get.json";
#[cfg(unix)]
const MANIFEST: &str = "deploy/app-secrets.yaml";

#[cfg(unix)]
/// A project whose index lists the catalog, an ordinary catalog beside it and
/// a Kubernetes `Secret` manifest, plus an untracked copy of the catalog.
fn hook_fixture() -> (PathBuf, PathBuf) {
    let (home, project) = fixture();
    write(&project.join(CATALOG), CATALOG_TEXT);
    write(&project.join(ORDINARY), CATALOG_TEXT);
    write(
        &project.join("drafts/kubernetes-secrets.json"),
        CATALOG_TEXT,
    );
    write(
        &project.join(MANIFEST),
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\n",
    );
    write_index(&project.join(".git"), &[CATALOG, ORDINARY, MANIFEST]);
    (home, project)
}

#[cfg(unix)]
fn hook(tool: serde_json::Value, home: &Path, project: &Path) -> guard_contracts::PreToolResultV1 {
    let controls = crate::pretool::workspace_contained_tests::controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "claude-code",
        "PreToolUse",
        &tool,
        Some(&controls),
        None,
        home.to_str(),
        project.to_str(),
    )
}

#[cfg(unix)]
fn read(path: &Path) -> serde_json::Value {
    serde_json::json!({"tool_name": "Read", "tool_input": {"file_path": path}})
}

#[cfg(unix)]
fn edit(path: &Path) -> serde_json::Value {
    serde_json::json!({"tool_name": "Edit", "tool_input": {
        "file_path": path, "old_string": "List", "new_string": "Show"
    }})
}

#[cfg(unix)]
fn bash(command: &str) -> serde_json::Value {
    serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}})
}

#[cfg(unix)]
#[test]
fn a_tracked_catalog_is_read_and_edited_like_any_document() {
    let (home, project) = hook_fixture();
    let calls: [(serde_json::Value, serde_json::Value); 4] = [
        (read(&project.join(CATALOG)), read(&project.join(ORDINARY))),
        (edit(&project.join(CATALOG)), edit(&project.join(ORDINARY))),
        (
            bash(&format!("sed -i 's/List/Show/' {CATALOG}")),
            bash(&format!("sed -i 's/List/Show/' {ORDINARY}")),
        ),
        (
            bash(&format!("perl -pi -e 's/List/Show/' {CATALOG}")),
            bash(&format!("perl -pi -e 's/List/Show/' {ORDINARY}")),
        ),
    ];
    for (named, ordinary) in calls {
        let named_result = hook(named.clone(), &home, &project);
        let ordinary_result = hook(ordinary, &home, &project);
        assert!(!named_result.action.sensitive_target, "{named}");
        assert_eq!(
            (named_result.reason_code, named_result.minimum_action),
            (ordinary_result.reason_code, ordinary_result.minimum_action),
            "{named}"
        );
    }
}

#[cfg(unix)]
#[test]
fn manifests_untracked_copies_and_credential_words_keep_the_signal() {
    let (home, project) = hook_fixture();
    for call in [
        read(&project.join(MANIFEST)),
        edit(&project.join(MANIFEST)),
        bash(&format!("sed -i 's/app/web/' {MANIFEST}")),
        read(&project.join("drafts/kubernetes-secrets.json")),
        bash("perl -pi -e 's/List/Show/' drafts/kubernetes-secrets.json"),
        // The edit itself names a credential word beside the tracked path.
        bash(&format!("sed -i 's/password/pass/' {CATALOG}")),
        bash(&format!("cat {CATALOG} > drafts/secrets-copy.json")),
    ] {
        assert!(
            hook(call.clone(), &home, &project).action.sensitive_target,
            "{call}"
        );
    }
}
