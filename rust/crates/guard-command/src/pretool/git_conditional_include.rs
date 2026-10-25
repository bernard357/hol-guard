//! Whether a conditional include in the session's effective Git
//! configuration could reach a repository that does not exist yet.
//!
//! `git init` and a local `git clone` build a repository from the
//! configuration the session's Git reads, so an `includeIf` that brought in
//! `init.templateDir` would hand the new repository hooks a later command
//! there would run. Developers routinely keep one `includeIf "gitdir:..."`
//! in their global configuration to carry a work identity, and Git applies
//! it only to repositories below the directory it names. A condition whose
//! literal prefix cannot stand at the front of the new repository's Git
//! directory never reaches it, so it leaves the command where it stands.

use std::path::Path;

/// Whether the conditional include that the effective-configuration key
/// `key` names could apply to a repository whose Git directory will be
/// `git_dir`. Only a `gitdir:` condition with a literal, absolute head is
/// decided; every other condition, and every pattern this reader does not
/// resolve, could apply.
pub(in crate::pretool) fn could_apply(key: &str, git_dir: &Path, home: Option<&str>) -> bool {
    const PREFIX: &str = "includeif.";
    if !key
        .get(..PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
    {
        return false;
    }
    let Some(condition) = condition(&key[PREFIX.len()..]) else {
        return true;
    };
    let Some(pattern) = gitdir_pattern(condition) else {
        return true;
    };
    let Some(resolved) = resolve(pattern, home) else {
        return true;
    };
    // Matching stops at the first wildcard: whatever follows it, the
    // characters before it must stand literally at the front of the path
    // Git compares. `**` is a wildcard too, so a pattern that could match
    // anywhere keeps its head empty and stays under review.
    let literal = &resolved[..resolved.find(['*', '?', '[']).unwrap_or(resolved.len())];
    fold(git_dir.to_string_lossy().as_ref()).starts_with(&fold(literal))
}

/// The condition of `<condition>.path`, the rest of an `includeIf` key, or
/// `None` for a conditional include this reader cannot read. Git lowercases
/// the section name and the condition with it, so every comparison here
/// folds case.
fn condition(rest: &str) -> Option<&str> {
    let (condition, name) = rest.rsplit_once('.')?;
    (name.eq_ignore_ascii_case("path") && !condition.is_empty()).then_some(condition)
}

/// The pattern of a `gitdir:` or `gitdir/i:` condition. Every other
/// condition - `onbranch:`, `hasconfig:` and anything Git adds - is `None`.
fn gitdir_pattern(condition: &str) -> Option<&str> {
    condition
        .strip_prefix("gitdir:")
        .or_else(|| condition.strip_prefix("gitdir/i:"))
        .filter(|pattern| !pattern.is_empty())
}

/// `pattern` as the absolute path Git compares, or `None` for a form this
/// reader does not resolve: an escape, a `~user` home, a value relative to
/// the file that wrote it, and a bare name, which Git reads as `**/<name>`
/// and so could stand anywhere.
fn resolve(pattern: &str, home: Option<&str>) -> Option<String> {
    if pattern.contains('\\') {
        return None;
    }
    if let Some(rest) = pattern.strip_prefix("~/") {
        let home = home?.trim_end_matches('/');
        return Some(format!("{home}/{rest}"));
    }
    (pattern.starts_with('/') && !pattern.starts_with("//")).then(|| pattern.to_owned())
}

/// The macOS and Windows volumes Git runs on fold case, and `gitdir/i`
/// folds it everywhere, so every comparison here does.
fn fold(value: &str) -> String {
    value.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::could_apply;
    use std::path::Path;

    const HOME: Option<&str> = Some("/Users/dev");

    #[test]
    fn a_work_identity_include_leaves_a_scratch_repository_alone() {
        assert!(!could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(!could_apply(
            "includeif.gitdir:/Users/dev/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
    }

    #[test]
    fn an_include_over_the_new_repository_applies() {
        assert!(could_apply(
            "includeif.gitdir:/private/tmp/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/Users/dev/Code/work/app/.git"),
            HOME,
        ));
    }

    #[test]
    fn case_never_decides_the_answer() {
        assert!(could_apply(
            "includeif.gitdir/i:/Private/TMP/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
    }

    #[test]
    fn an_unresolved_pattern_or_condition_applies() {
        for key in [
            "includeif.onbranch:main.path",
            "includeif.hasconfig:remote.*.url:https://example.invalid/.path",
            "includeif.gitdir:work/.path",
            "includeif.gitdir:./sibling/.path",
            "includeif.gitdir:~other/work/.path",
            "includeif.gitdir:~/Code/wo\\rk/.path",
            "includeif.gitdir:.path",
            "includeif.gitdir:/Users/dev/Code/work/",
        ] {
            assert!(
                could_apply(key, Path::new("/private/tmp/scratch/.git"), HOME),
                "{key}"
            );
        }
    }

    #[test]
    fn a_wildcard_head_still_rules_a_distant_path_out() {
        assert!(!could_apply(
            "includeif.gitdir:/Users/dev/Code/*/app/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(could_apply(
            "includeif.gitdir:/Users/dev/Code/*/app/.path",
            Path::new("/Users/dev/Code/work/app/.git"),
            HOME,
        ));
    }

    #[test]
    fn an_ordinary_setting_is_not_a_conditional_include() {
        for key in [
            "init.templatedir",
            "include.path",
            "core.hookspath",
            "includeif",
        ] {
            assert!(
                !could_apply(key, Path::new("/private/tmp/scratch/.git"), HOME),
                "{key}"
            );
        }
    }

    #[test]
    fn a_home_relative_pattern_needs_a_home() {
        assert!(could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            None,
        ));
    }
}
