//! The checkout forms `start_point` names a commit for.

fn words(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_string).collect()
}

fn point(line: &str) -> Option<String> {
    super::start_point(&words(line)).map(str::to_string)
}

#[test]
fn a_plain_switch_names_the_branch_it_moves_to() {
    assert_eq!(point("switch main").as_deref(), Some("main"));
    assert_eq!(point("checkout main").as_deref(), Some("main"));
    assert_eq!(
        point("switch feat/signed-lane").as_deref(),
        Some("feat/signed-lane")
    );
}

#[test]
fn the_previous_branch_is_the_ref_git_spells_it() {
    assert_eq!(point("switch -").as_deref(), Some("@{-1}"));
    assert_eq!(point("checkout -").as_deref(), Some("@{-1}"));
}

#[test]
fn a_detaching_checkout_names_the_commit_it_detaches_at() {
    assert_eq!(point("switch --detach").as_deref(), Some("HEAD"));
    assert_eq!(point("switch --detach HEAD").as_deref(), Some("HEAD"));
    assert_eq!(point("checkout --detach v1.2.0").as_deref(), Some("v1.2.0"));
}

#[test]
fn a_created_branch_still_names_its_start_point() {
    assert_eq!(
        point("switch -c feat/lane origin/main").as_deref(),
        Some("origin/main")
    );
    assert_eq!(
        point("checkout -b feat/lane origin/main").as_deref(),
        Some("origin/main")
    );
}

#[test]
fn a_forced_or_pathspec_checkout_names_nothing() {
    // `-f` overwrites the working tree, and `--` restores files from the
    // index over whatever is there.
    assert_eq!(point("checkout -f main"), None);
    assert_eq!(point("checkout -- README.md"), None);
    assert_eq!(point("checkout main -- src"), None);
    assert_eq!(point("switch --discard-changes main"), None);
    assert_eq!(point("checkout --force --detach HEAD"), None);
    assert_eq!(point("restore main"), None);
    assert_eq!(point("switch"), None);
}
