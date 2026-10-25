//! The execution sink's peel, answered by the classification that decided it.
//!
//! The sink used to recover the core command, its directory and its output
//! handling by lexing the text a second time in Python. That copy carried its
//! own sibling-repository rule, which could not read a Windows owner SID, so
//! it peeled checkouts the classifier had refused and handed the sandbox a
//! core no receipt covered. One peel now serves both: the classifier answers
//! the shape it already resolved, and the sink runs that answer.

use super::{contained_wrapper, workspace_contained, PathContext};
use crate::{parse_command, CanonicalCommandV1, CommandModelRequestV1};
use std::path::PathBuf;

/// The sink refused the shape and runs the command whole in its sandbox, as
/// the Python peel's `ValueError` did.
pub const CONTAINED_WRAPPER_PLAN_UNSUPPORTED: &str = "native_contained_wrapper_plan_unsupported";

/// How the sink handles the core's output.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedOutput {
    /// `head`, `tail`, `pipe` or `all`.
    pub kind: &'static str,
    /// The line count a `head`/`tail` stage keeps; zero for the other kinds.
    pub count: u32,
    /// The core ended in `2>&1`, so the sink merges stderr into stdout.
    pub merge_stderr: bool,
    /// The label a trailing `; echo "label$?"` prints before the status.
    pub status_label: Option<String>,
    /// Each stage of a `pipe` chain, as its program followed by arguments.
    pub stages: Vec<Vec<String>>,
}

/// The core the sink runs, and where.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainedWrapperCore {
    pub core: String,
    pub directory: PathBuf,
    pub output: Option<ContainedOutput>,
}

/// Everything the sink asks about one command.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContainedWrapperPlan {
    /// The peel, or `None` when nothing is wrapped.
    pub plan: Option<ContainedWrapperCore>,
    /// Set when the shape is wrapped but unsupported.
    pub refusal: Option<&'static str>,
    /// The sibling repository holding `plan.directory`, when that directory
    /// lies outside the sink's workspace.
    pub directory_sibling_root: Option<PathBuf>,
    /// The sibling repository an absolute script runs from, when no wrapper
    /// was peeled.
    pub anchored_sibling_root: Option<PathBuf>,
    /// The sibling repository holding the directory the caller asked about,
    /// independently of the command.
    pub project_root: Option<PathBuf>,
}

/// Peel `command` the way the sink runs it.
///
/// `workspace` is the sandbox root; `cwd` the directory the command was issued
/// from. The environment proofs are set here because the sink peels only a
/// command the classifier already admitted under the real environment, and the
/// Python peel this replaces consulted no environment at all.
pub fn contained_wrapper_plan(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
    project_root_query: Option<&str>,
) -> ContainedWrapperPlan {
    let project_root = project_root_query.and_then(|directory| {
        contained_wrapper::sibling_project_root(std::path::Path::new(directory), home_dir?)
    });
    ContainedWrapperPlan {
        project_root,
        ..wrapper_plan(
            command,
            workspace,
            cwd,
            home_dir,
            SINK_PEELS_RELATIVE_INSIDE,
        )
    }
}

/// Only a host with no workspace sandbox peels an `&&`-joined relative `cd`
/// that stays inside the workspace; elsewhere the sandbox runs that text
/// whole. The resident answers for the host it runs on, which is the sink's.
const SINK_PEELS_RELATIVE_INSIDE: bool = cfg!(windows);

/// The peel alone, without the standalone directory question.
fn wrapper_plan(
    command: &str,
    workspace: &str,
    cwd: Option<&str>,
    home_dir: Option<&str>,
    peels_relative_inside: bool,
) -> ContainedWrapperPlan {
    let Ok(model) = parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    }) else {
        return ContainedWrapperPlan::default();
    };
    let context = PathContext {
        home_dir,
        cwd: cwd.or(Some(workspace)),
        cdpath_unset: true,
        shell_home_matches: true,
        ..PathContext::default()
    };
    let sink = contained_wrapper::SinkContext {
        workspace,
        peels_relative_inside,
    };
    if let Some(peeled) = contained_wrapper::contained_plan(&model, context, Some(sink)) {
        let directory = peeled
            .directory
            .clone()
            .unwrap_or_else(|| PathBuf::from(cwd.unwrap_or(workspace)));
        let directory_sibling_root = outside_root(&directory, workspace, home_dir);
        return ContainedWrapperPlan {
            plan: Some(ContainedWrapperCore {
                core: peeled.core_text.clone(),
                directory,
                output: output_handling(&peeled),
            }),
            refusal: None,
            directory_sibling_root,
            ..ContainedWrapperPlan::default()
        };
    }
    // `cd <sibling root> && a && b` runs the whole list in that root; a filter
    // after `a && b` would apply to `b` alone, so none is peeled there.
    match workspace_contained::sibling::sibling_run(&model, context) {
        Some((root, Some(rest))) => {
            let Some(core) = joined_text(&rest) else {
                return ContainedWrapperPlan {
                    refusal: Some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED),
                    ..ContainedWrapperPlan::default()
                };
            };
            let directory_sibling_root = outside_root(&root, workspace, home_dir);
            ContainedWrapperPlan {
                plan: Some(ContainedWrapperCore {
                    core,
                    directory: root,
                    output: None,
                }),
                refusal: None,
                directory_sibling_root,
                ..ContainedWrapperPlan::default()
            }
        }
        Some((root, None)) => ContainedWrapperPlan {
            refusal: wrapped_shape(&model).then_some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED),
            anchored_sibling_root: Some(root),
            ..ContainedWrapperPlan::default()
        },
        None => ContainedWrapperPlan {
            refusal: wrapped_shape(&model).then_some(CONTAINED_WRAPPER_PLAN_UNSUPPORTED),
            ..ContainedWrapperPlan::default()
        },
    }
}

/// The sibling repository holding `directory`, when it lies outside the
/// workspace. The sink rebases its approved root there.
fn outside_root(
    directory: &std::path::Path,
    workspace: &str,
    home_dir: Option<&str>,
) -> Option<PathBuf> {
    let root = std::fs::canonicalize(workspace).ok()?;
    if directory.starts_with(&root) {
        return None;
    }
    contained_wrapper::sibling_project_root(directory, home_dir?)
}

/// The source text of every segment left after the `cd`.
fn joined_text(rest: &CanonicalCommandV1) -> Option<String> {
    let first = rest.segments.first()?;
    let last = rest.segments.last()?;
    contained_wrapper::text(rest, first.span.start, last.span.end)
}

fn output_handling(peeled: &contained_wrapper::ContainedPlan) -> Option<ContainedOutput> {
    if peeled.stages.is_empty() && !peeled.merge_stderr && peeled.status_label.is_none() {
        return None;
    }
    let (kind, count) = match peeled.stages.as_slice() {
        [] => ("all", 0),
        [stage] if stage.first().is_some_and(|name| name == "head") => ("head", stage_count(stage)),
        [stage] if stage.first().is_some_and(|name| name == "tail") => ("tail", stage_count(stage)),
        _ => ("pipe", 0),
    };
    Some(ContainedOutput {
        kind,
        count,
        merge_stderr: peeled.merge_stderr,
        status_label: peeled.status_label.clone(),
        stages: if kind == "pipe" {
            peeled.stages.clone()
        } else {
            Vec::new()
        },
    })
}

fn stage_count(stage: &[String]) -> u32 {
    stage
        .get(1)
        .and_then(|count| count.parse::<u32>().ok())
        .unwrap_or(0)
}

/// A shape the Python peel would have accepted or rejected outright, rather
/// than left alone: a `cd` prefix, an output filter, a merge or a status echo.
fn wrapped_shape(model: &CanonicalCommandV1) -> bool {
    model
        .segments
        .first()
        .is_some_and(|segment| segment.executable.as_deref() == Some("cd"))
        || model
            .segments
            .iter()
            .any(|segment| segment.pipeline_index != 0)
        || model.segments.iter().any(|segment| {
            segment
                .arguments
                .last()
                .is_some_and(|argument| argument == "2>&1")
        })
        || model
            .segments
            .last()
            .is_some_and(|segment| contained_wrapper::status_echo(model, segment))
}

#[cfg(test)]
#[path = "contained_wrapper_plan_tests.rs"]
mod tests;
