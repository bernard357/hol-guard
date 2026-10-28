//! Git reads that follow steps the user allowed.
//!
//! The Git extension has no permission for reads such as `git rev-parse HEAD`,
//! `git merge-base` or `git branch --show-current`: Guard proves them on its
//! own. That proof holds for a read that runs first, or after steps that are
//! themselves proven. After a step the user allowed (`git push`, `git checkout
//! main`), the benign proof no longer carries a read that takes any argument,
//! so `git push && git rev-parse HEAD` lost the Allow its push was given.
//!
//! A read that only looks up refs and objects in the current repository does
//! not depend on anything such a step changes. It names no file, runs in the
//! same directory, and the Git floor still probes the configuration it runs
//! under. This module counts it as covered when the steps before it are.
//!
//! The same holds for a Docker listing Guard proves on its own (`docker ps`,
//! `docker images`, `docker logs`): none of them reads a project file, so a
//! Git step before it cannot change what it does.

use super::PathContext;
use crate::CanonicalCommandV1;
use std::collections::BTreeSet;

/// Reads that look up refs, commits or objects and never the working tree.
/// Each is one the Git floor probes (`git_config::execution_free`), so the
/// pager, diff driver or textconv setting it would run is still checked where
/// it runs. Status, diff, grep and the index listings are not here: their
/// proof reads the tree's attributes and index, which an allowed checkout or
/// pull changes.
const REF_READS: &[&str] = &[
    "rev-parse",
    "rev-list",
    "merge-base",
    "show-ref",
    "for-each-ref",
    "branch",
    "describe",
    "cat-file",
    "tag",
    "log",
    "show",
    "shortlog",
    "reflog",
];

/// The Git ref reads and Docker listings in `model` that the steps before
/// them leave covered.
///
/// `benign` holds the segments the native benign proof covers and `covered`
/// every segment covered so far, by that proof, an enabled permission or a
/// GitHub grant. A read qualifies when it is proven safe on its own, takes no
/// leading Git option (so `-C` and `--git-dir` cannot route it elsewhere), and
/// every earlier step is covered and either a Git command or benign. A step
/// that is neither, such as an allowed `ln`, could repoint the directory the
/// read runs in, so it ends the run.
pub(crate) fn git_reads_after_allowed_steps(
    model: &CanonicalCommandV1,
    context: PathContext<'_>,
    benign: &BTreeSet<usize>,
    covered: &BTreeSet<usize>,
) -> Vec<usize> {
    if model.confidence != "exact" || model.path_overridden || !model.wrapper_chain.is_empty() {
        return Vec::new();
    }
    let cwd = super::segment_proof::verified_cwd_compound_context(model, context);
    if cwd.is_none()
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"))
    {
        return Vec::new();
    }
    let proof_context = PathContext {
        creates_nothing: super::search::command_creates_nothing(model),
        cwd: cwd.as_deref().or(context.cwd),
        ..context
    };
    let mut added = Vec::new();
    for (index, segment) in model.segments.iter().enumerate() {
        let git = git_segment(segment);
        if covered.contains(&index) {
            if git || benign.contains(&index) {
                continue;
            }
            break;
        }
        let read = if git {
            ref_read(model, segment, proof_context)
        } else {
            super::docker_reads::proven_segment(model, segment, proof_context)
        };
        if !read {
            break;
        }
        added.push(index);
    }
    added
}

fn git_segment(segment: &crate::CommandSegmentV1) -> bool {
    segment
        .executable
        .as_deref()
        .is_some_and(|executable| super::executable_basename(executable) == "git")
}

fn ref_read(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> bool {
    let stripped = super::without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some((operation, rest)) = segment.arguments.split_first() else {
        return false;
    };
    !segment.path_overridden
        && segment.wrapper_chain.is_empty()
        && segment
            .environment_names
            .iter()
            .all(|name| crate::command_compatibility::inert_git_environment_name(name))
        && REF_READS.contains(&operation.as_str())
        && !super::git_history_reads::cleans_working_tree(operation, rest)
        // The Git floor probes each of these reads, so the proof may lean on
        // that probe for the helper context, as the floor's own order check
        // does.
        && super::segment_proof::exact_safe_segment_with_context(model, segment, true, context)
}

#[cfg(test)]
mod tests {
    use super::REF_READS;

    #[test]
    fn working_tree_reads_are_not_ref_reads() {
        for operation in ["status", "diff", "grep", "ls-files", "blame", "check-attr"] {
            assert!(!REF_READS.contains(&operation), "{operation}");
        }
    }
}
