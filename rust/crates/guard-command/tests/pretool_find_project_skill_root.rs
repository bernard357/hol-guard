//! A checkout carries its own `.agents/skills` tree, and an agent reads the
//! project's skills by walking it. A plain listing of the session folder
//! already prints those names, so the names-only walk that prints the same
//! ones is ordinary work. A hidden project directory that is not a skills
//! tree, an `.agents` folder holding state of its own, and a hidden or
//! credential-named folder below the tree all keep review.
use crate::pretool_home_layout_reads::{assert_decision, layout};
use std::path::Path;

fn project(checkout: &Path) {
    std::fs::create_dir_all(checkout.join(".agents/skills/x")).unwrap();
    std::fs::write(
        checkout.join(".agents/skills/x/SKILL.md"),
        "---\nname: x\n---\nSynthetic skill body.\n",
    )
    .unwrap();
    std::fs::create_dir_all(checkout.join(".worktrees/inner")).unwrap();
    std::fs::write(checkout.join(".worktrees/inner/notes.md"), "# Inert\n").unwrap();
}

#[test]
fn a_projects_own_skill_tree_is_walked_without_review() {
    let layout = layout("project-skill-root");
    let checkout = layout.org.join("app-portal");
    project(&checkout);
    for command in [
        "find .agents -maxdepth 3 -type f -print",
        "find .agents/skills -type d",
        "find .agents/skills/x -type f",
        "find .agents -maxdepth 3 -type f -print && ls .agents/skills",
    ] {
        assert_decision(&checkout, &layout.home, command, true);
    }
}

#[test]
fn a_hidden_project_directory_that_is_not_a_skill_tree_still_asks() {
    let layout = layout("project-not-skill-root");
    let checkout = layout.org.join("app-portal");
    project(&checkout);
    assert_decision(
        &checkout,
        &layout.home,
        "find .worktrees -maxdepth 2 -type f -print",
        false,
    );
}

#[test]
fn an_agents_folder_holding_state_of_its_own_still_asks() {
    let layout = layout("project-agents-state");
    let checkout = layout.org.join("service-api");
    project(&checkout);
    std::fs::create_dir_all(checkout.join(".agents/state")).unwrap();
    std::fs::write(checkout.join(".agents/state/notes.md"), "# Inert\n").unwrap();
    assert_decision(
        &checkout,
        &layout.home,
        "find .agents -maxdepth 3 -type f -print",
        false,
    );
}

#[test]
fn a_hidden_or_credential_named_folder_below_the_project_tree_still_asks() {
    let layout = layout("project-skill-screens");
    let checkout = layout.org.join("app-portal");
    project(&checkout);
    for directory in [".agents/skills/.private", ".agents/skills/credentials"] {
        std::fs::create_dir_all(checkout.join(directory)).unwrap();
    }
    for command in [
        "find .agents/skills/.private -type f",
        "find .agents/skills/credentials -type f",
    ] {
        assert_decision(&checkout, &layout.home, command, false);
    }
}
