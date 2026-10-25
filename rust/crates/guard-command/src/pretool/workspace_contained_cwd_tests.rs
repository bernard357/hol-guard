use crate::pretool::workspace_contained_tests::workspace;
use std::path::Path;

fn shaped(command: &str, workspace: &Path) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    super::super::command_shape(&model, workspace, Some(command)).is_some()
}

/// `cd build && cmake ..` is how every out-of-tree build is spelled. The
/// parent step returns to the workspace root the descent just left, so the
/// path never leaves the sandbox the shape builds.
#[test]
fn a_parent_step_after_a_proven_descent_stays_inside_the_workspace() {
    let ws = workspace("cwd-parent", true);
    std::fs::create_dir_all(ws.join("build")).unwrap();
    std::fs::create_dir_all(ws.join("build/sub")).unwrap();
    for command in [
        "cd build && ls ..",
        "cd build && ls -la ..",
        "cd build && cat ../package.json",
        "cd build/sub && cat ../../package.json",
        "cd build && ls .. && ls .",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    for command in [
        // No descent to spend: the step leaves the workspace.
        "ls ..",
        "cat ../package.json",
        // One descent, two steps.
        "cd build && ls ../..",
        "cd build/sub && cat ../../../package.json",
        // `;` runs the second command whether or not the descent succeeded,
        // so the shallower shell decides.
        "cd build; ls ..",
        // A descent the file system does not confirm proves no depth.
        "cd absent && ls ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// `CDPATH` makes bash search its own list before the current directory, so a
/// bare `cd etc` can land outside the workspace while the walk here joins the
/// name onto the directory it is tracking. No segment may spend a step then.
#[test]
fn a_command_that_mentions_cdpath_spends_no_descent() {
    let ws = workspace("cwd-cdpath", true);
    std::fs::create_dir_all(ws.join("etc")).unwrap();
    for command in [
        "CDPATH=/ cd etc && cat ../etc/passwd",
        "export CDPATH=/ && cd etc && cat ../etc/passwd",
        "CDPATH=/ cd etc && ls ..",
        // zsh ties the same search to a lowercase `cdpath` array, which an
        // uppercase-only match read as an ordinary assignment.
        "cdpath=/ cd etc && cat ../etc/passwd",
        "export cdpath=/ && cd etc && ls ..",
        "CdPath=/ cd etc && ls ..",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}
