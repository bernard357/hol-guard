//! Operand safety for a staged diff written without the `--` separator.

use crate::codex_output_env::{Ctx, GitCheck, InspectionHost};
use crate::sfrs_git_cached_diff::cached_diff_operands_are_safe;
use guard_contracts::CompoundGitSegmentV1;

/// Accepts the pathspecs the resident host accepts: repository-relative names.
struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        !values.is_empty()
            && values.iter().all(|value| {
                !value.is_empty()
                    && !value.starts_with(['-', '/', '~'])
                    && !value.split('/').any(|component| component == "..")
            })
    }
    fn git_inspection_segment(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        true
    }
    fn git_show_config(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        true
    }
    fn standalone_git_routine(&self, _: &[CompoundGitSegmentV1], _: bool, _: Option<&str>) -> bool {
        false
    }
}

fn safe(operands: &[&str]) -> bool {
    let host = Host;
    let ctx = Ctx::new(&host, "/", "/");
    let args: Vec<String> = operands.iter().map(|item| (*item).to_owned()).collect();
    cached_diff_operands_are_safe(&args, &ctx)
}

#[test]
fn bare_pathspecs_read_the_index_like_the_separator_form() {
    assert!(safe(&["--cached", "package.json"]));
    assert!(safe(&["--cached", "src"]));
    assert!(safe(&["--staged", "src/app.ts", "package.json"]));
    assert!(safe(&["--cached", "HEAD", "package.json"]));
    assert!(safe(&["--cached", "--stat", "src"]));
}

#[test]
fn operand_free_and_separator_forms_keep_their_answers() {
    assert!(safe(&["--cached"]));
    assert!(safe(&["--cached", "--name-only"]));
    assert!(safe(&["--cached", "--", "package.json"]));
    assert!(!safe(&["--name-only"]));
    assert!(!safe(&["--cached", "--", "../outside"]));
}

#[test]
fn an_unlisted_option_never_reaches_the_pathspec_check() {
    assert!(!safe(&["--cached", "--output=/tmp/leak.diff"]));
    assert!(!safe(&["--cached", "-O/tmp/order"]));
    assert!(!safe(&["--cached", "--ext-diff"]));
    assert!(!safe(&["--cached", "../outside"]));
    assert!(!safe(&["--cached", "/etc/passwd"]));
}

#[test]
fn the_pathspec_count_stays_bounded() {
    let mut operands = vec!["--cached".to_owned()];
    operands.extend((0..17).map(|index| format!("src/file{index}.ts")));
    let host = Host;
    let ctx = Ctx::new(&host, "/", "/");
    assert!(!cached_diff_operands_are_safe(&operands, &ctx));
}
