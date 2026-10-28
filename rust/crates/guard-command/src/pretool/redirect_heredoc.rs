//! Which program a quoted heredoc may feed.
//!
//! The projection strips the heredoc and the redirects and hands the rest of
//! the command back to be evaluated in full, so a quoted heredoc adds exactly
//! one thing: literal bytes on standard input. The body is not expanded, reads
//! no file and reaches no network. The only way it can matter is a program
//! that runs, applies or installs what it reads.
//!
//! The list is positive because that risk has no shape to test for. A shell
//! and an interpreter are the obvious cases, but `xargs` builds a command line
//! from stdin, `psql`, `mysql` and `sqlite3` execute it, `patch` and
//! `git apply` apply it, `tar -x` and `dd` write it, `crontab -` installs it
//! and `kubectl apply -f -` deploys it. None of them looks like an
//! interpreter, so naming the programs that only read is the only test that
//! stays correct as programs are added.

use crate::CanonicalCommandV1;

/// Programs that read standard input as data. Each prints, counts, filters or
/// reshapes what it reads; none runs, applies or installs it.
const FILTERS: &[&str] = &[
    "cat", "column", "cut", "diff", "fmt", "fold", "grep", "head", "jq", "nl", "rev", "sort",
    "tail", "tee", "tr", "uniq", "wc", "yq",
];

/// Whether the command is one plain filter spelled by name, with no wrapper,
/// environment assignment or path override, so the heredoc body it reads is
/// data and nothing else. The caller still proves every file the command
/// writes on its own.
pub(super) fn reads_data(model: &CanonicalCommandV1) -> bool {
    model.wrapper_chain.is_empty()
        && !model.path_overridden
        && model.segments.len() == 1
        && model.segments[0].wrapper_chain.is_empty()
        && model.segments[0].environment_names.is_empty()
        && !model.segments[0].path_overridden
        && model.segments[0]
            .executable
            .as_deref()
            .is_some_and(|executable| FILTERS.contains(&executable))
}

/// The bare `cat` the caller may stand a no-op in for. Reading standard input
/// is the whole of what it does, so once the write is proven there is nothing
/// left for the command itself to do. Every other filter, and `cat` with
/// arguments, still has the files it names read.
pub(super) fn is_bare_cat(model: &CanonicalCommandV1) -> bool {
    model.segments.len() == 1
        && model.segments[0].executable.as_deref() == Some("cat")
        && model.segments[0].arguments.is_empty()
}
