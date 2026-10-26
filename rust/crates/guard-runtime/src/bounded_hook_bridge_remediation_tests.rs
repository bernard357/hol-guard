use std::path::{Path, PathBuf};

use super::*;

const MARKER: &str = "HOL Guard blocked this action under the native command extension policy.";
const BARE: &str =
    " Run `hol-guard command controls recover-authority` in a terminal to restore the protected control floor.";

fn home() -> PathBuf {
    PathBuf::from("/Users/casey")
}

/// A block from the home the bare command would find keeps that command.
#[test]
fn the_default_home_keeps_the_short_command() {
    let guard_home = home().join(".hol-guard");
    assert_eq!(remediation_for_home(Some(&guard_home), Some(&home())), BARE);
}

/// A bridge reading a home the bare command would not find names it, so the
/// person repairs the install that is blocking them rather than another one.
#[test]
fn another_home_is_named_on_the_command() {
    assert_eq!(
        remediation_for_home(Some(Path::new("/opt/guards/ci")), Some(&home())),
        " Run `hol-guard command --home /opt/guards/ci controls recover-authority` in a terminal to restore the protected control floor."
    );
}

/// The named home is pasted into a shell, so it is quoted for one.
#[test]
fn a_named_home_is_quoted_for_the_shell() {
    assert_eq!(
        remediation_for_home(Some(Path::new("/opt/shared guards/.hol-guard")), Some(&home())),
        " Run `hol-guard command --home '/opt/shared guards/.hol-guard' controls recover-authority` in a terminal to restore the protected control floor."
    );
}

/// With either side unknown there is nothing to compare, and a runtime that
/// cannot tell the two apart has nothing to add to the command.
#[test]
fn an_unknown_home_on_either_side_keeps_the_short_command() {
    assert_eq!(remediation_for_home(None, Some(&home())), BARE);
    assert_eq!(remediation_for_home(None, None), BARE);
    assert_eq!(
        remediation_for_home(Some(Path::new("/opt/guards/ci")), None),
        BARE
    );
}

/// The whole sentence travels with the block, naming the home the bridge read.
#[test]
fn an_authority_block_carries_the_recovery_command() {
    assert_eq!(
        zcode_authority_block_reason(MARKER, None),
        format!("{MARKER}{BARE}")
    );
}

/// A reason that is not an authority block, and one that already offers the
/// command, are both left exactly as the daemon wrote them.
#[test]
fn other_reasons_are_left_alone() {
    assert_eq!(
        zcode_authority_block_reason("HOL Guard blocked this action.", None),
        "HOL Guard blocked this action."
    );
    let offered = format!("{MARKER} Run `hol-guard command controls recover-authority`.");
    assert_eq!(zcode_authority_block_reason(&offered, None), offered);
}
