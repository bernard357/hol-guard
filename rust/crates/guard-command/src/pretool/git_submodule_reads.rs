//! The one `git submodule` spelling that only prints: `submodule status`.
//!
//! Every other submodule verb moves work. `add`, `init`, `deinit`, `update`,
//! `sync`, `set-url`, `set-branch` and `absorbgitdirs` write configuration,
//! refs or the worktree, and `foreach` runs whatever command it is handed, so
//! none of them belongs here. `summary` prints a diff, so it would need the
//! diff machinery's own proof rather than this one.
//!
//! `status` prints one line per submodule: the recorded object id, the path,
//! and the ref it describes. Git reaches that answer from the superproject —
//! it reads the superproject index, so a configured `core.fsmonitor` there can
//! still start, which the configuration probe clears — and then runs `git
//! describe` inside each submodule against the recorded id. A describe of a
//! named object pages nothing, converts nothing and refreshes no index.
//!
//! `--recursive` is the line this grammar will not cross. It re-enters each
//! submodule with `submodule--helper status --recursive`, which reads that
//! submodule's own index under that submodule's own configuration. A
//! `core.fsmonitor` set in a submodule executes under `--recursive` and does
//! not under the plain form, and the superproject-rooted configuration probe
//! never reads it, so the recursive walk keeps its review.
//!
//! Bare `git submodule` is `git submodule status`, and is admitted as one.
//! So are the shared options Git's synopsis places before the verb, `--quiet`
//! and `--cached`: they choose how much the listing prints and name no path.

/// Whether `arguments`, the tokens after the `submodule` subcommand, name the
/// printing form.
pub(crate) fn read_form(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    // Git's synopsis puts the shared options before the verb: `git submodule
    // [--quiet] [--cached] <command>`. They choose how much the listing
    // prints and name no path, so a leading one leaves the form unchanged.
    let rest = match words
        .iter()
        .position(|word| !matches!(*word, "-q" | "--quiet" | "--cached"))
    {
        // Bare `git submodule`, and the shared options alone, run `status`.
        None => return true,
        Some(index) => &words[index..],
    };
    match rest.split_first() {
        Some((&"status", rest)) => status(rest),
        _ => false,
    }
}

/// `submodule status` with the options that only choose how much it prints,
/// and plain path operands. Every other option, `--recursive` above all,
/// keeps its review.
fn status(rest: &[&str]) -> bool {
    let mut operands = false;
    rest.iter().all(|argument| match *argument {
        _ if operands => operand(argument),
        "-q" | "--quiet" | "--cached" => true,
        "--" => {
            operands = true;
            true
        }
        _ => operand(argument),
    })
}

/// A submodule path as `status` takes it: a plain name, never an option and
/// never a magic pathspec.
fn operand(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('-') && !value.starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::read_form;

    fn form(arguments: &[&str]) -> bool {
        read_form(
            &arguments
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn printing_forms_are_read_forms() {
        assert!(form(&[]));
        assert!(form(&["status"]));
        assert!(form(&["status", "-q"]));
        assert!(form(&["status", "--quiet"]));
        assert!(form(&["status", "--cached"]));
        assert!(form(&["status", "vendor/lib"]));
        assert!(form(&["status", "--cached", "--", "vendor/lib"]));
    }

    /// Git's synopsis is `git submodule [--quiet] [--cached] <command>`, so
    /// both spellings may stand before the verb, and alone they still run
    /// `status`.
    #[test]
    fn shared_options_may_precede_the_verb() {
        assert!(form(&["-q", "status"]));
        assert!(form(&["--quiet", "status"]));
        assert!(form(&["--cached", "status"]));
        assert!(form(&["--quiet", "--cached", "status", "vendor/lib"]));
        assert!(form(&["-q"]));
        assert!(form(&["--quiet"]));
        assert!(form(&["--cached"]));
        // The verb still decides: a leading option admits nothing else.
        assert!(!form(&["--quiet", "foreach", "git", "status"]));
        assert!(!form(&["-q", "update"]));
        assert!(!form(&["--quiet", "status", "--recursive"]));
    }

    #[test]
    fn a_recursive_walk_keeps_its_review() {
        // It reads each submodule's own configuration, which the
        // superproject-rooted probe never saw.
        assert!(!form(&["status", "--recursive"]));
        assert!(!form(&["status", "--cached", "--recursive"]));
        assert!(!form(&["status", "--recursive", "vendor/lib"]));
    }

    #[test]
    fn verbs_that_move_work_keep_their_review() {
        for verb in [
            "add",
            "init",
            "deinit",
            "update",
            "sync",
            "foreach",
            "set-url",
            "set-branch",
            "absorbgitdirs",
            "summary",
        ] {
            assert!(!form(&[verb]), "{verb} is not a read form");
        }
        assert!(!form(&["foreach", "git", "status"]));
    }

    #[test]
    fn unknown_options_and_magic_pathspecs_keep_their_review() {
        assert!(!form(&["status", "--unknown"]));
        assert!(!form(&["status", ":(glob)**/id_rsa"]));
        assert!(!form(&["status", "--", "--recursive"]));
        assert!(!form(&["status", "--", ":/"]));
    }
}
