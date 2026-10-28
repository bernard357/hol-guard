#![cfg(unix)]

//! `git worktree add <path> ... && cd <path> && git commit ...`: work in the
//! checkout the same command creates, under the user's Git and GitHub Allow.
//!
//! Entering the new checkout is what `git -C <path>` does for one step, and
//! the `-C` spelling already runs under that Allow. The `cd` spelling has to
//! run the same way, while any step the Allow does not reach keeps its review
//! and a denied step still blocks the whole command.

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Every Git and GitHub permission in the packaged catalog set to `state`,
/// with `overrides` applied on top, as the Extensions page writes it.
fn git_github(
    state: &str,
    overrides: &[(&str, &str)],
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls: Vec<_> = program
        .extensions
        .iter()
        .flat_map(|extension| extension.permissions.iter())
        .map(|permission| permission.permission_id.as_str())
        .filter(|id| {
            id.starts_with("command.git.permission.")
                || id.starts_with("command.github.permission.")
        })
        .map(|id| {
            let state = overrides
                .iter()
                .find(|(target, _)| *target == id)
                .map_or(state, |(_, state)| *state);
            json!({"target_kind":"permission", "target_id":id, "state":state})
        })
        .collect();
    let value = json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
        "trust_digest":program.trust_digest, "health":"protected", "revision":1,
        "managed_revision":0, "effective_digest":"", "layers":[{
            "schema_version":"1.0.0", "kind":"local-admin", "catalog_digest":program.catalog_digest,
            "global_lockdown":false, "controls":controls
        }]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(value).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn evaluate(
    home: &Path,
    cwd: &Path,
    harness: &str,
    command: &str,
    controls: &guard_command::native_command_controls::CompiledNativeCommandControls,
) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

fn directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn git(home: &Path, repository: &Path, arguments: &[&str]) {
    assert!(std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .args(arguments)
        .status()
        .unwrap()
        .success());
}

/// `org/app` below a fresh home, one commit deep, with a GitHub `origin`
/// whose `main` is that commit. `org/app-taken` already exists beside it.
fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-entry-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = home.join("org/app");
    for path in [&root, &home, &repository, &home.join("org/app-taken")] {
        directory(path);
    }
    git(
        &home,
        &repository,
        &["init", "--quiet", "--initial-branch=main"],
    );
    git(
        &home,
        &repository,
        &["config", "user.name", "Guard Fixture"],
    );
    git(
        &home,
        &repository,
        &["config", "user.email", "guard-fixture@example.invalid"],
    );
    git(
        &home,
        &repository,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/app-portal.git",
        ],
    );
    std::fs::write(repository.join("README.md"), "fixture\n").unwrap();
    git(&home, &repository, &["add", "."]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    (cleanup, home, repository)
}

const ADD: &str = "git worktree add -b review ../app-review origin/main";

/// The `cd` spellings of work a developer does in a fresh checkout. Each has
/// a `git -C ../app-review` twin that runs under the same Allow.
fn entered(home: &Path) -> Vec<String> {
    let absolute = home.join("org/app-review");
    let absolute = absolute.display();
    vec![
        format!("{ADD} && cd ../app-review && git commit --allow-empty -m 'Start review'"),
        format!(
            "{ADD} && cd ../app-review && git add -A && git commit -m 'Update copy' \
             && git push -u origin review"
        ),
        format!("{ADD}; cd ../app-review && git commit --allow-empty -m 'Start review'"),
        "git worktree add ../app-review -b review origin/main && cd ../app-review \
         && git push -u origin review"
            .to_owned(),
        format!(
            "git worktree add -b review {absolute} origin/main && cd {absolute} \
             && git commit --allow-empty -m 'Start review' && git push -u origin review"
        ),
    ]
}

#[test]
fn an_allowed_chain_runs_in_the_worktree_it_creates() {
    let (_cleanup, home, repository) = repository("allowed");
    let controls = git_github("enabled", &[]);
    let mut failures = Vec::new();
    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for command in entered(&home) {
            let result = evaluate(&home, &repository, harness, &command, &controls);
            if result.minimum_action != "allow" {
                failures.push(format!(
                    "{harness}: {command}: {} {}",
                    result.minimum_action, result.reason_code
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_worktree_chain_waits_without_an_allow() {
    let (_cleanup, home, repository) = repository("default");
    let controls = fixture::github_controls("default");
    for command in entered(&home).iter().take(2) {
        let result = evaluate(&home, &repository, "omp", command, &controls);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

#[test]
fn a_denied_step_in_the_worktree_blocks_the_chain() {
    let (_cleanup, home, repository) = repository("denied");
    let controls = git_github("enabled", &[("command.git.permission.commit", "disabled")]);
    let command =
        format!("{ADD} && cd ../app-review && git commit --allow-empty -m 'Start review'");
    let result = evaluate(&home, &repository, "omp", &command, &controls);
    assert_eq!(result.minimum_action, "block", "{}", result.reason_code);
}

/// The `cd` is covered only when it enters exactly the new checkout and only
/// Git and GitHub steps follow it.
#[test]
fn other_entries_and_steps_keep_their_review() {
    let (_cleanup, home, repository) = repository("reviewed");
    let controls = git_github("enabled", &[]);
    for command in [
        format!("{ADD} && cd ../app-other && git commit --allow-empty -m 'Start review'"),
        format!("{ADD} && cd .. && git -C app-review commit --allow-empty -m 'Start review'"),
        format!("{ADD} && cd ../app-review && npm run build && git push -u origin review"),
        format!("{ADD} && cd ../app-review && python3 build.py && git commit -am 'Build'"),
        format!("{ADD} && cd ../app-review && git commit -am 'Build' && cd .. && ls"),
        format!("{ADD} || cd ../app-review && git commit --allow-empty -m 'Start review'"),
        "git worktree add -b review ../app-taken origin/main && cd ../app-taken \
         && git commit --allow-empty -m 'Start review'"
            .to_owned(),
    ] {
        let result = evaluate(&home, &repository, "omp", &command, &controls);
        assert_ne!(
            result.minimum_action, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}
