//! Where `cd` and `pushd` may move a contained command: a literal directory
//! below the workspace, or a fresh directory under the run's private
//! temporary directory, which only this run can write. Operands after either
//! move are still judged as workspace paths, so a `cd` that fails leaves
//! nothing the checks did not see. Such a fresh directory may also be the
//! value of a variable that later programs read.

use crate::pretool::generic::chain_literals::inert::temp_cd;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use std::path::Path;

/// A literal directory at or below the workspace, with no parent step.
pub(super) fn below(target: &str, workspace: &Path) -> bool {
    let path = Path::new(target);
    !target.is_empty()
        && !target.starts_with(['~', '-'])
        && !target.contains('$')
        && path
            .components()
            .all(|component| !matches!(component, std::path::Component::ParentDir))
        && (path.is_relative() || path.starts_with(workspace))
}

/// Whether `found` holds for any directory a tool's own project lookup would
/// read from `directory`: that directory first, then each parent up to the
/// workspace root and no further. `npx`, `cargo`, `go` and `uv` all resolve
/// the project they act on by ascending from where they run, so a run that
/// stands in a subdirectory of the workspace reaches the manifest, the
/// installed tool or the environment the workspace root holds. Bounding the
/// walk at that root is what keeps the proof inside the sandbox: nothing
/// above the workspace is ever read, so the admission still rests on what the
/// workspace itself holds.
///
/// `directory` is checked wherever it points, which is what the single-
/// directory checks did. The walk only starts when it stays below the
/// workspace with no parent step in it, so a path that already climbed out
/// cannot carry the ascent further out.
pub(super) fn found_from(
    directory: &Path,
    workspace: &Path,
    found: impl Fn(&Path) -> bool,
) -> bool {
    if found(directory) {
        return true;
    }
    if !directory.starts_with(workspace)
        || directory
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return false;
    }
    let mut probe = directory;
    while probe != workspace {
        let Some(parent) = probe.parent() else {
            return false;
        };
        probe = parent;
        if found(probe) {
            return true;
        }
    }
    false
}

/// Whether `target`, the only operand of a `cd` or `pushd`, is a directory
/// the sandbox bounds. `temp_fixed` says nothing rebinds `TMPDIR`, so the
/// stand-in for `"$(mktemp -d)"` is a directory `mktemp` creates under the
/// run's private temporary directory.
pub(super) fn bounded(target: &str, workspace: &Path, temp_fixed: bool) -> bool {
    below(target, workspace) || (temp_fixed && temp_cd::private_directory(target))
}

/// Whether every temporary stand-in in the command is the only operand of a
/// `cd` or `pushd`, or the value of a private assignment. Anywhere else it
/// would pass the path checks as a missing absolute path while the real
/// command names the private directory.
pub(super) fn stand_ins_only_entered(model: &CanonicalCommandV1) -> bool {
    let mentions = temp_cd::mentions(&model.normalized_text);
    mentions == 0
        || mentions
            == model
                .segments
                .iter()
                .filter(|segment| enters_private(segment) || assigns_private(model, segment))
                .count()
}

fn enters_private(segment: &CommandSegmentV1) -> bool {
    segment.executable.as_deref().is_some_and(|executable| {
        matches!(
            crate::pretool::executable_basename(executable),
            "cd" | "pushd"
        )
    }) && matches!(
        segment.arguments.as_slice(),
        [target] if temp_cd::private_directory(target)
    )
}

/// Whether `segment` only sets a variable to the stand-in, or a literal path
/// below it, as `export NAME=VALUE` or a bare `NAME=VALUE`. The launcher runs
/// the raw text, whose `mktemp` makes that directory under the run's private
/// `TMPDIR`, so the variable carries only a path the sandbox bounds into the
/// programs after it. Nothing may rebind `TMPDIR`, and the name must appear
/// nowhere else, so no later word expands the stand-in.
pub(super) fn assigns_private(model: &CanonicalCommandV1, segment: &CommandSegmentV1) -> bool {
    let alone = match segment.executable.as_deref() {
        Some("export") => segment.environment_names.is_empty() && segment.arguments.len() == 1,
        Some(_) => false,
        None => segment.environment_names.len() == 1 && segment.tokens.len() == 1,
    };
    alone
        && segment.wrapper_chain.is_empty()
        && !super::reach::rebinds_private_temp(&model.normalized_text)
        && temp_cd::private_assignment(segment.text.trim(), &model.normalized_text)
}

// The tests spell the workspace path inside POSIX shell text, which a
// Windows `\\?\C:\...` path cannot be written in.
#[cfg(all(test, unix))]
#[path = "workspace_contained_cd_tests.rs"]
mod tests;

// [`found_from`] reads paths rather than shell text, so its bound is checked
// on every platform the sandbox runs on.
#[cfg(test)]
#[path = "workspace_contained_cd_walk_tests.rs"]
mod walk_tests;
