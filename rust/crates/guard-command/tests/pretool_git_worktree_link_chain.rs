#![cfg(unix)]

//! `git worktree add <path> <ref> && ln -s <dir> <path>/<sub>/<name>`: a
//! dependency directory shared with the checkout the same command creates.

use crate::git_helper_fixture as fixture;
use fixture::{evaluate_pre_tool_envelope_with_context, FixtureCleanup};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn evaluate(home: &Path, cwd: &Path, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&fixture::github_controls("enabled")),
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

/// `org/app` below a fresh home: a tracked `dashboard` directory holding a
/// tracked `vendor` directory and `index.js`, a tracked link `linked ->
/// dashboard`, and ignored `node_modules` directories installed at the root
/// and in `dashboard`. A directory outside the repository stands beside it.
fn repository(name: &str) -> (FixtureCleanup, PathBuf, PathBuf) {
    let unique = format!(
        "{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    );
    let root = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(format!("guard-worktree-link-{name}-{unique}"));
    let cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = home.join("org/app");
    for path in [&root, &home, &repository] {
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
    directory(&repository.join("dashboard/vendor"));
    std::fs::write(repository.join("dashboard/index.js"), "\n").unwrap();
    std::fs::write(repository.join("dashboard/vendor/keep.txt"), "\n").unwrap();
    std::fs::write(repository.join(".gitignore"), "node_modules/\n").unwrap();
    std::os::unix::fs::symlink("dashboard", repository.join("linked")).unwrap();
    git(&home, &repository, &["add", "."]);
    git(&home, &repository, &["commit", "--quiet", "-m", "fixture"]);
    git(
        &home,
        &repository,
        &["update-ref", "refs/remotes/origin/main", "HEAD"],
    );
    directory(&repository.join("node_modules/vitest"));
    directory(&repository.join("dashboard/node_modules/vite"));
    directory(&home.join("org/outside/node_modules"));
    (cleanup, home, repository)
}

fn assert_allowed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_eq!(
        result.minimum_action, "allow",
        "{command}: {}",
        result.reason_code
    );
}

fn assert_reviewed(home: &Path, cwd: &Path, command: &str) {
    let result = evaluate(home, cwd, command);
    assert_ne!(result.minimum_action, "allow", "{command}");
}

/// Links into a tracked directory of the new checkout, or its root, under a
/// name the checked-out commit does not track.
#[test]
fn links_into_the_new_worktree_are_allowed() {
    let (_cleanup, home, repository) = repository("allowed");
    let app = repository.display();
    let checkout = home.join("org/app-x");
    let checkout = checkout.display();
    for command in [
        format!("git worktree add {checkout} -b br-x origin/main 2>&1 | tail -1 && ln -s {app}/dashboard/node_modules {checkout}/dashboard/node_modules"),
        format!("git worktree add ../app-x -b br-x origin/main && ln -s {app}/node_modules ../app-x/node_modules"),
        "git worktree add ../app-x -b br-x origin/main && ln -s ../../app/dashboard/node_modules ../app-x/dashboard/node_modules".to_owned(),
        format!("git worktree add ../app-x origin/main && ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/dashboard/node_modules ../app-x/dashboard/node_modules"),
        format!("git worktree add -b br-x ../app-x origin/main && ln -s {app}/node_modules ../app-x/node_modules && git -C ../app-x status --short"),
    ] {
        assert_allowed(&home, &repository, &command);
    }
}

/// A link through a tracked link, onto a tracked name, into a directory the
/// commit does not track, outside the checkout, to a directory of another
/// repository, twice to one path, or after a separator that does not wait
/// for the add keeps its review.
#[test]
fn other_links_after_a_worktree_add_stay_reviewed() {
    let (_cleanup, home, repository) = repository("reviewed");
    let app = repository.display();
    let add = "git worktree add -b br-x ../app-x origin/main";
    for tail in [
        format!("&& ln -s {app}/node_modules ../app-x/linked/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/vendor"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/index.js"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/INDEX.JS"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/missing/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x/dashboard/.cache"),
        format!("&& ln -s {app}/dashboard/node_modules ../elsewhere/node_modules"),
        format!("&& ln -s {app}/dashboard/node_modules ../app-x"),
        "&& ln -s ../../outside/node_modules ../app-x/dashboard/node_modules".to_owned(),
        format!("&& ln -s {app}/.git ../app-x/dashboard/node_modules"),
        format!("&& ln -sf {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && ln -s {app}/node_modules {}/node_modules", home.join("org/app-x").display()),
        format!("; ln -s {app}/node_modules ../app-x/node_modules"),
        format!("|| ln -s {app}/node_modules ../app-x/node_modules"),
        format!("&& ln -s {app}/node_modules ../app-x/node_modules && touch ../app-x/node_modules/x"),
    ] {
        assert_reviewed(&home, &repository, &format!("{add} {tail}"));
    }
}
