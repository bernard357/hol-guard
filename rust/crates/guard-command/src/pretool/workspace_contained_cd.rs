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
///
/// A bare relative operand is read as the directory of that name below the
/// run's cwd, which the decision elsewhere admits only against proof that the
/// caller exported no `CDPATH`. Containment needs no such proof: the launcher
/// builds the run's environment from an allow-list
/// (`restricted_pytest::environment::filter`), `CDPATH` is on no list, and a
/// `CDPATH` the command sets itself is refused by [`sets_search_path`] before
/// the shape is admitted. So the search a shell would make cannot happen
/// inside the sandbox, and the name resolves to exactly the directory this
/// reading names. `environment_tests` pins the allow-list half, so a name
/// added to it later cannot quietly undo this.
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

/// Whether `segment` sets `CDPATH`, the list a shell searches before the
/// current directory for a bare relative `cd` operand. The launcher hands the
/// sandbox no such list, but the command text is run as written, so a run that
/// sets one itself would land a `cd` the checks read as one directory in
/// another — `CDPATH=/ cd etc` enters `/etc`. zsh ties the same search to a
/// lowercase `cdpath` array and `export cdpath=...` there sets both, so the
/// name is matched without case, in a leading assignment and in the arguments
/// of the builtins that set one. `readonly` and `local` set a variable as
/// much as `export` does, and `NAME+=value` appends to it, which from unset
/// is the same as setting it, so the name is read with a trailing `+` off.
/// A leading `CDPATH+=/` is not a name the parser reads as an assignment, so
/// the segment's own leading words are checked for that spelling too.
pub(super) fn sets_search_path(segment: &CommandSegmentV1) -> bool {
    fn is_search_path(word: &str) -> bool {
        let name = word.split('=').next().unwrap_or(word);
        name.trim()
            .trim_end_matches('+')
            .eq_ignore_ascii_case("CDPATH")
    }
    segment
        .environment_names
        .iter()
        .any(|name| is_search_path(name))
        || segment
            .tokens
            .iter()
            .take_while(|token| token.contains('='))
            .any(|token| is_search_path(token))
        || (matches!(
            segment
                .executable
                .as_deref()
                .map(crate::pretool::executable_basename),
            Some("export" | "declare" | "typeset" | "setenv" | "set" | "readonly" | "local")
        ) && segment
            .arguments
            .iter()
            .any(|argument| is_search_path(argument)))
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

// [`sets_search_path`] reads the command's own text, so the shells it has to
// answer for are the ones every platform the sandbox runs on may use.
#[cfg(test)]
#[path = "workspace_contained_cd_search_path_tests.rs"]
mod search_path_tests;
