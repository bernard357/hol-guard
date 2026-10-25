use super::found_from;
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("hol-guard-cd-walk-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::canonicalize(&root).unwrap()
}

fn marked(directory: &Path) -> bool {
    directory.join("marker").is_file()
}

#[test]
fn a_marker_at_the_workspace_root_is_found_from_a_directory_below_it() {
    let root = scratch("below");
    let workspace = root.join("workspace");
    let deep = workspace.join("packages/web/src");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(workspace.join("marker"), "").unwrap();

    assert!(found_from(&deep, &workspace, marked));
    assert!(found_from(&workspace, &workspace, marked));
}

#[test]
fn the_nearest_marker_below_the_root_is_enough() {
    let root = scratch("nearest");
    let workspace = root.join("workspace");
    let crate_directory = workspace.join("crates/engine");
    let deep = crate_directory.join("src");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(crate_directory.join("marker"), "").unwrap();

    assert!(found_from(&deep, &workspace, marked));
}

#[test]
fn nothing_above_the_workspace_root_is_read() {
    let root = scratch("bounded");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("packages/web")).unwrap();
    // The marker sits beside the workspace, where the walk must never reach.
    std::fs::write(root.join("marker"), "").unwrap();

    assert!(!found_from(
        &workspace.join("packages/web"),
        &workspace,
        marked
    ));
    assert!(!found_from(&workspace, &workspace, marked));
}

#[test]
fn a_directory_outside_the_workspace_is_read_but_never_walked_from() {
    let root = scratch("outside");
    let workspace = root.join("workspace");
    let sibling = root.join("sibling");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(sibling.join("inner")).unwrap();
    std::fs::write(sibling.join("marker"), "").unwrap();

    // The directory itself is still read, as the single-directory checks did.
    assert!(found_from(&sibling, &workspace, marked));
    // Its parents are not, so a path that already left the workspace cannot
    // climb to a marker the workspace does not hold.
    assert!(!found_from(&sibling.join("inner"), &workspace, marked));
}

#[test]
fn a_parent_step_in_the_path_stops_the_walk() {
    let root = scratch("parent-step");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("packages")).unwrap();
    std::fs::write(root.join("marker"), "").unwrap();

    // `workspace/../..` is lexically below the workspace, and walking up from
    // it would read directories above the root.
    let climbed = workspace.join("..").join("..");
    assert!(!found_from(&climbed, &workspace, marked));
}
