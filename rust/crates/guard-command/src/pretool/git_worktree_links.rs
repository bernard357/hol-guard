//! What a fresh checkout holds at one path before anything else writes to it:
//! the proof behind `git worktree add <path> <ref> && ln -s <dir>
//! <path>/<sub>/<name>`, which shares a dependency directory with the new
//! checkout. Right after the add, the checkout holds exactly the tree of the
//! commit it checked out, since the worktree proof has already ruled out
//! hooks and filters that could write anything else.

use std::path::Path;
use std::time::Instant;

use super::hooks::tree_entry;
use super::{git_query_with_args, prepared_git_command};

/// Whether `parent` (`""` for the checkout root) is a directory the commit
/// tracks, reached through tracked directories only, and the commit tracks
/// no entry named `name` in it under any letter case. A tracked symbolic
/// link on the way is refused: `ln` would follow it out of the checkout.
/// `None` is doubt.
#[allow(clippy::too_many_arguments)]
pub(in super::super) fn tracked_directory_with_free_name(
    executable: &str,
    leading: &[String],
    commit: &str,
    parent: &str,
    name: &str,
    context: super::super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let probe_deadline = Instant::now() + super::super::git_probe::PROBE_BUDGET;
    let deadline = deadline.unwrap_or(probe_deadline).min(probe_deadline);
    if Instant::now() >= deadline || name.is_empty() || Path::new(parent).is_absolute() {
        return None;
    }
    let (base, _binary, _cwd, _home) =
        prepared_git_command(executable, context, execution_environment)?;
    let tree = if parent.is_empty() {
        format!("{commit}^{{tree}}")
    } else {
        // Git looks a path up through trees only, so an entry reached through
        // a tracked link or submodule is not listed at all.
        if tree_entry(&base, leading, commit, parent, deadline)?.as_deref() != Some("040000") {
            return Some(false);
        }
        format!("{commit}:{parent}")
    };
    let (status, listing) = git_query_with_args(
        &base,
        leading,
        &["ls-tree", "-z", "--name-only", &tree],
        deadline,
        super::super::git_probe::LISTING_LIMIT,
    )?;
    if !status.success() {
        return None;
    }
    Some(
        !listing
            .split(|byte| *byte == 0)
            .any(|entry| entry.eq_ignore_ascii_case(name.as_bytes())),
    )
}
