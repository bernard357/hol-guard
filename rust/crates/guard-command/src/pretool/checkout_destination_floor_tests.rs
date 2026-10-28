// The cases spell POSIX paths into shell text and link directories.
#![cfg(unix)]

use super::protected_checkout_destination;
use crate::pretool::PathContext;
use std::path::PathBuf;

struct Layout {
    root: PathBuf,
    home: String,
    workspace: String,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A home holding `projects/service-api` (with `.git`), a Codex-style
/// worktree checkout, a launch-agent folder and a link that points at it.
fn layout(name: &str) -> Layout {
    let root = std::env::temp_dir().join(format!("guard-checkout-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("projects/service-api");
    for directory in [
        workspace.join(".git/hooks"),
        workspace.join(".github/workflows"),
        home.join("Library/LaunchAgents"),
        home.join(".codex/worktrees/abc/service-api"),
        home.join(".claude"),
        root.join("scratch"),
    ] {
        std::fs::create_dir_all(directory).unwrap();
    }
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::os::unix::fs::symlink(home.join("Library/LaunchAgents"), home.join("agents-link"))
        .unwrap();
    let canonical = |path: PathBuf| path.canonicalize().unwrap().to_str().unwrap().to_owned();
    Layout {
        home: canonical(home),
        workspace: canonical(workspace),
        root: root.canonicalize().unwrap(),
    }
}

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

fn protected_in(layout: &Layout, cwd: &str, command: &str) -> bool {
    let command = command
        .replace("HOME", &layout.home)
        .replace("ROOT", layout.root.to_str().unwrap());
    let context = PathContext {
        home_dir: Some(layout.home.as_str()),
        cwd: Some(cwd),
        ..PathContext::default()
    };
    protected_checkout_destination(&model(&command), context)
}

#[test]
fn checkouts_into_auto_loaded_locations_stay_a_floor() {
    let layout = layout("protected");
    for command in [
        "git worktree add ~/Library/LaunchAgents/wt origin/main",
        "git worktree add HOME/Library/LaunchAgents/wt origin/main",
        "git worktree add HOME/.claude/agents origin/main",
        "git worktree add HOME/.claude/wt origin/main",
        "git worktree add HOME/.codex/wt origin/main",
        "git worktree add HOME/.zcode/wt origin/main",
        "git worktree add HOME/.config/autostart/wt origin/main",
        "git worktree add HOME/bin/wt origin/main",
        "git worktree add .git/hooks/wt origin/main",
        "git worktree add .github/workflows/wt origin/main",
        "git worktree add -b wt HOME/.claude/agents origin/main",
        "git worktree add --detach HOME/.claude/agents HEAD",
        "git worktree move ../svc HOME/Library/LaunchAgents/wt",
        "git fetch origin main && git worktree add HOME/.claude/agents origin/main",
        "git worktree add ../ok origin/main && git worktree add HOME/.codex/x origin/main",
        "git clone https://github.com/example-org/x.git HOME/Library/LaunchAgents/x",
        "git clone git@github.com:example-org/x.git HOME/.claude/agents",
        "git clone --depth=1 https://github.com/example-org/x.git ~/.claude/agents",
        "git clone --separate-git-dir=HOME/.claude/x.git https://example.com/x.git x",
        "git init HOME/.zcode/x",
        "git --git-dir=HOME/.claude/x.git init",
        "git submodule add https://github.com/example-org/x.git .husky/x",
        // The directory a compound enters, or `-C`, is where the checkout lands.
        "cd HOME/.claude && git clone https://github.com/example-org/x.git agents",
        "cd ~/Library/LaunchAgents && git clone https://github.com/example-org/x.git",
        "git -C HOME/.claude worktree add agents origin/main",
        "git -CHOME/.claude clone https://github.com/example-org/x.git agents",
        // A link is judged where it leads.
        "git worktree add HOME/agents-link/wt origin/main",
        // A word or directory the text cannot fix fails closed.
        "git worktree add $HOME/x origin/main",
        "cd - && git clone https://github.com/example-org/x.git x",
        "git worktree add ~other/wt origin/main",
    ] {
        assert!(
            protected_in(&layout, &layout.workspace, command),
            "{command}"
        );
    }
}

#[test]
fn ordinary_checkouts_are_not_a_floor() {
    let layout = layout("ordinary");
    for command in [
        "git worktree add ../sibling -b br origin/main",
        "git worktree add -b br ../sibling origin/main",
        "git worktree add HOME/projects/svc-p -b br-p origin/main 2>&1 | tail -3; cd HOME/projects/svc-p && git rev-parse HEAD",
        "git worktree add ROOT/scratch/contrast --detach 0123abcd",
        "git fetch origin main && git worktree add --detach ROOT/scratch/c2 0123abcd",
        "git worktree add ../hgp-a origin/main && cd ../hgp-a && git status --short",
        "git worktree add ~/projects/svc-q origin/main",
        "git worktree move ../svc ../svc-moved",
        "git clone https://github.com/example-org/x.git",
        "git clone git@github.com:example-org/x.git HOME/projects/x",
        "git clone --branch main --depth 1 https://github.com/example-org/x.git ../x",
        "git init ../fresh",
        "git submodule add https://github.com/example-org/x.git vendor/x",
        // Not a checkout: the floor never looks.
        "git worktree list",
        "git worktree remove ../hgp-a",
        "git status --short",
        "ls ~/.claude",
    ] {
        assert!(!protected_in(&layout, &layout.workspace, command), "{command}");
    }
}

#[test]
fn a_workspace_under_a_hidden_folder_judges_siblings_by_their_own_name() {
    let layout = layout("hidden-parent");
    let workspace = format!("{}/.codex/worktrees/abc/service-api", layout.home);
    assert!(!protected_in(
        &layout,
        &workspace,
        "git worktree add ../sibling origin/main"
    ));
    for command in [
        "git worktree add HOME/.codex/skills/x origin/main",
        "git worktree add ../.claude origin/main",
        "git worktree add ../sibling/.git/hooks origin/main",
    ] {
        assert!(protected_in(&layout, &workspace, command), "{command}");
    }
}

#[test]
fn without_a_cwd_only_the_spelling_is_judged() {
    let context = PathContext::default();
    assert!(protected_checkout_destination(
        &model("git worktree add .claude/agents origin/main"),
        context
    ));
    assert!(!protected_checkout_destination(
        &model("git worktree add ../sibling origin/main"),
        context
    ));
}
