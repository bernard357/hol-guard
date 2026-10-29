//! Checks run in a linked worktree the same command creates, such as
//! `git worktree add --detach ../app-fix HEAD && cd ../app-fix && bun run build`.
//!
//! The new checkout does not exist when Guard answers, so the routes that
//! contain `cd <checkout> && bun run build` for an existing sibling checkout
//! have nothing to read. Each part is judged on its own instead, as the
//! extension controls set it: the add must pass as if it were the whole
//! command, and the checks must pass, or run contained, from the repository
//! root the new checkout copies. The sink then creates the checkout outside the
//! sandbox, once Guard proves the add again, and judges
//! `cd <checkout> && <checks>` once more against the real checkout before
//! anything in it runs. The chain therefore admits nothing its parts would
//! not admit separately.
use super::allowed;
use crate::pretool::workspace_contained::{admitted_workspace, mark_contained};
use crate::pretool::PathContext;
use crate::{parse_command, CommandModelRequestV1};
use guard_contracts::PreToolResultV1;
use serde_json::Value;

/// The reason this split carries. The sink reads it from the receipt to plan
/// the same split, so it must stay an exact constant.
pub(crate) const REASON_TEXT: &str = concat!(
    "HOL Guard creates this linked worktree directly, outside the sandbox, once it ",
    "proves the `git worktree add` again, then judges the rest of the command again ",
    "against the new checkout and runs it there: directly when it passes on its own, ",
    "otherwise inside a protected workspace sandbox (no network, no home access, no ",
    "PTY or Docker socket), where every program it starts, including children of an ",
    "interpreter, runs contained and can write only the checkout, $TMPDIR and a ",
    "private scratch $HOME.",
);

/// The parts of a split chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Parts {
    /// The `git worktree add`, run outside the sandbox.
    pub(crate) add: String,
    /// `cd <checkout> && <checks>`, judged again once the checkout exists.
    pub(crate) entered: String,
    /// The checks alone.
    pub(crate) checks: String,
}

/// `git worktree add [options] <checkout> [ref] && cd <checkout> && <checks>`,
/// split at its first two `&&`, or `None` for any other shape. The `cd` must
/// name the checkout exactly as the add spelled it, so both resolve to the
/// same directory from the same shell. Classification and the sink both split
/// with this.
pub(crate) fn split(text: &str) -> Option<Parts> {
    let model = parse_command(&CommandModelRequestV1 {
        command: text.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .ok()?;
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || text.trim() != model.normalized_text
    {
        return None;
    }
    let [add, cd, first_check, ..] = model.segments.as_slice() else {
        return None;
    };
    if [add, cd, first_check]
        .iter()
        .any(|segment| segment.pipeline_index != 0 || !segment.environment_names.is_empty())
    {
        return None;
    }
    let is_git = add
        .executable
        .as_deref()
        .is_some_and(|value| crate::pretool::executable_basename(value) == "git");
    let (destination, moved) = crate::pretool::worktree_add::destination(add)?;
    // A `-C` moves where a relative checkout lands, but not where `cd` goes.
    if !is_git || (moved && !std::path::Path::new(destination).is_absolute()) {
        return None;
    }
    if cd.executable.as_deref() != Some("cd")
        || cd.arguments.len() != 1
        || cd.arguments[0] != destination
        // The add's parser takes only an unquoted `~`; a quoted one in the
        // `cd` would name a literal directory instead.
        || (destination.starts_with('~')
            && !crate::pretool::directory_targets::home_targets_unquoted(cd))
    {
        return None;
    }
    let joined = |left: usize| {
        crate::pretool::worktree_add::separator_between(&model, left, left + 1)
            .as_deref()
            .map(str::trim)
            == Some("&&")
    };
    if !joined(0) || !joined(1) {
        return None;
    }
    let from = |at: usize| -> String { model.normalized_text.chars().skip(at).collect() };
    let head: String = model.normalized_text.chars().take(cd.span.start).collect();
    let add = head.trim().strip_suffix("&&")?.trim_end();
    let entered = from(cd.span.start);
    let checks = from(first_check.span.start);
    let (entered, checks) = (entered.trim(), checks.trim());
    if add.is_empty() || checks.is_empty() {
        return None;
    }
    Some(Parts {
        add: add.to_owned(),
        entered: entered.to_owned(),
        checks: checks.to_owned(),
    })
}

/// The chain as a proven add followed by checks judged again in the new
/// checkout, or `raw` unchanged when either part would not pass on its own.
pub(crate) fn rejudge(
    raw: PreToolResultV1,
    payload: &Value,
    context: PathContext<'_>,
    evaluate: impl Fn(&Value) -> PreToolResultV1,
) -> PreToolResultV1 {
    if raw.minimum_action != "review" || raw.action.sensitive_target || !characterised(&raw) {
        return raw;
    }
    let Some(command) = super::super::extract_generic_signals(payload)
        .ok()
        .and_then(|signals| signals.command)
    else {
        return raw;
    };
    let Some(parts) = split(&command) else {
        return raw;
    };
    // The checks are judged where the command was issued, which stands in for
    // the new checkout only at the root of the repository it copies.
    if !admitted_workspace(context).is_some_and(|workspace| workspace.join(".git").exists()) {
        return raw;
    }
    let judged = |part: &str| {
        let projected = super::super::payload_with_command(payload, &command, part);
        (projected != *payload).then(|| evaluate(&projected))
    };
    if !judged(&parts.add).is_some_and(|add| allowed(&add)) {
        return raw;
    }
    // Checks that pass on their own run directly once judged again; the rest
    // must run contained as they would from the repository root.
    let admitted = judged(&parts.checks).is_some_and(|checks| {
        allowed(&checks)
            || (checks.minimum_action == "sandbox-required"
                && checks.reason_code == crate::pretool::workspace_contained::REASON
                && checks.reason != super::REASON_TEXT
                && checks.reason != REASON_TEXT)
    });
    if !admitted {
        return raw;
    }
    let mut result = raw;
    mark_contained(&mut result);
    result.reason = REASON_TEXT.into();
    result
}

/// The chain's extension evidence loaded and matched without doubt. Any
/// permission may contribute, such as the Git worktree control or a package
/// extension for the checks, because each part is judged again with the same
/// controls and keeps the answer it gets on its own.
fn characterised(result: &PreToolResultV1) -> bool {
    result
        .command_extensions
        .as_ref()
        .is_some_and(|extensions| {
            extensions.evaluation_error.is_none()
                && extensions.binding.uncertainty_count == 0
                && extensions
                    .observations
                    .iter()
                    .all(|observation| observation.uncertainty_reasons.is_empty())
                && extensions
                    .permission_observations
                    .iter()
                    .all(|observation| {
                        observation.mcp_tool.is_none() && observation.uncertainty_reasons.is_empty()
                    })
        })
}

#[cfg(test)]
#[path = "contained_worktree_add_tests.rs"]
mod tests;
