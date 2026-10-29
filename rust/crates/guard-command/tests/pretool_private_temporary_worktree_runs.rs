//! Agents often put a linked worktree in the per-user temporary directory
//! (`git worktree add "$TMPDIR/<name>"`) and work in it from the main
//! checkout: `cd <worktree> && bun run build`, or a local commit there. That
//! directory is as much the user's as home, so the work runs the way it would
//! in a worktree beside the checkout, under either spelling of the path. The
//! shared temporary directory itself and a plain folder in it that is no
//! checkout still get no such run.
#![cfg(target_os = "macos")]

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::{Path, PathBuf};

/// A package whose build runs the local Vite entrypoint.
fn package(directory: &Path) {
    let scripts = r#"{"scripts":{"build":"vite build","test":"node --test"}}"#;
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("package.json"), scripts).unwrap();
    let entry = directory.join("node_modules/vite/bin/vite.js");
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::fs::write(entry, "").unwrap();
}

/// The session, a scratch folder below the private temporary directory, and
/// a linked worktree of the session's checkout inside it.
fn temporary_worktree(label: &str) -> (Session, PathBuf, PathBuf, Cleanup) {
    let session = session(label);
    let temporary = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert!(
        temporary.starts_with("/private/var/folders"),
        "expected the per-user temporary directory, got {}",
        temporary.display()
    );
    let nonce = crate::unique_nanos::unique_nanos();
    let scratch = temporary.join(format!("guard-temp-run-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&scratch).unwrap();
    let cleanup = Cleanup(scratch.clone());
    let checkout = scratch.join("workspace");
    git(
        &session.home,
        &session.primary,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            "temp-run",
            checkout.to_str().unwrap(),
        ],
    );
    package(&checkout);
    package(&checkout.join("dashboard"));
    (session, scratch, checkout, cleanup)
}

/// The path through the `/var` alias, as `$TMPDIR` spells it.
fn alias(path: &Path) -> PathBuf {
    Path::new("/var").join(path.strip_prefix("/private/var").unwrap())
}

fn outcome(session: &Session, command: &str) -> (String, String) {
    let result = session.evaluate_at(command, &session.primary);
    (result.minimum_action, result.reason_code)
}

#[test]
fn builds_in_a_temporary_worktree_run_contained() {
    let (session, _scratch, checkout, _cleanup) = temporary_worktree("temp-run-build");
    for spelled in [checkout.clone(), alias(&checkout)] {
        let wt = spelled.display();
        for command in [
            format!("cd {wt} && bun run build"),
            format!("cd {wt}/dashboard && bun run build"),
            format!("cd {wt}/dashboard && bun run build 2>&1 | tail -20"),
            format!("cd {wt} && npm run test"),
        ] {
            let (action, reason) = outcome(&session, &command);
            assert_eq!(
                (action.as_str(), reason.as_str()),
                ("sandbox-required", "native_workspace_containment_required"),
                "{command}"
            );
        }
    }
}

#[test]
fn local_commits_in_a_temporary_worktree_are_quiet() {
    let (session, _scratch, checkout, _cleanup) = temporary_worktree("temp-run-commit");
    for spelled in [checkout.clone(), alias(&checkout)] {
        let wt = spelled.display();
        for command in [
            format!("cd {wt} && git add -A && git commit -m \"fix: align spacing\""),
            format!("cd {wt} && git status --short"),
        ] {
            let (action, reason) = outcome(&session, &command);
            assert!(
                matches!(action.as_str(), "allow" | "sandbox-required"),
                "{command}: {action} {reason}"
            );
        }
    }
}

#[test]
fn the_temporary_directory_and_plain_folders_in_it_get_no_run() {
    let (session, scratch, checkout, _cleanup) = temporary_worktree("temp-run-plain");
    let plain = scratch.join("plain");
    package(&plain);
    let temporary = scratch.parent().unwrap().to_path_buf();
    let (plain, temporary, wt) = (plain.display(), temporary.display(), checkout.display());
    for command in [
        format!("cd {plain} && bun run build"),
        format!("cd {temporary} && bun run build"),
        format!("cd {wt} && bun add left-pad"),
        format!("cd {wt} && bun run build && rm -rf {temporary}"),
        format!("cd {wt} && git push origin HEAD"),
    ] {
        let (action, reason) = outcome(&session, &command);
        assert!(
            !matches!(action.as_str(), "allow" | "sandbox-required"),
            "{command}: {action} {reason}"
        );
    }
}

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
