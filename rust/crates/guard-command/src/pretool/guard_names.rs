//! Which arguments name Guard's own state, programs or installation for the
//! fixed floor that no extension Allow settles.
//!
//! Git and the shell's directory changes take repository paths, refs and
//! remote URLs. A checkout called `hol-guard-pr-12`, a pathspec such as
//! `scripts/hol-guard.wxs` or a remote `https://host/org/hol-guard.git` is the
//! user's work, not Guard. For those programs an argument names Guard only
//! when it reaches Guard's state directory, an installed Guard program or the
//! desktop application. Other programs keep the plain name screen.

/// Programs whose arguments are judged by [`names_guard_location`].
const LOCATION_PROGRAMS: &[&str] = &["git", "cd", "pushd"];

/// Executable and package names Guard installs.
const GUARD_PROGRAMS: &[&str] = &[
    "hol-guard",
    "plugin-guard",
    "hol-guard-runtime",
    "hol_guard",
];

/// Directories an installed program lives in. A Guard program name directly
/// below one of them is Guard's installation rather than a checkout.
const INSTALL_PARENTS: &[&str] = &[
    "bin",
    "sbin",
    "scripts",
    "venvs",
    "tools",
    "site-packages",
    "dist-packages",
    "cellar",
    "opt",
    "programs",
    "program files",
    "program files (x86)",
    "applications",
];

/// Suffixes an installed program or application carries on some platforms.
const PROGRAM_SUFFIXES: &[&str] = &[".exe", ".cmd", ".bat", ".ps1", ".app"];

/// Whether `program`'s arguments are judged by where they point rather than
/// by the plain name screen.
pub(super) fn judged_by_location(segment: &crate::CommandSegmentV1) -> bool {
    LOCATION_PROGRAMS.contains(&crate::command_compatibility::basename(segment).as_str())
}

/// Whether a path, ref or remote argument reaches Guard's state directory,
/// an installed Guard program or the desktop application.
///
/// Text with whitespace, or a leading `!`, is shell text a Git alias or
/// option could run, so it keeps the plain name screen.
pub(super) fn names_guard_location(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase().replace('\\', "/");
    if names_guard_state(&lowered) {
        return true;
    }
    if remote_url(&lowered) {
        return false;
    }
    let components: Vec<&str> = lowered.split('/').map(str::trim).collect();
    if components
        .iter()
        .any(|component| matches!(*component, "hol guard" | "hol guard.app"))
    {
        return true;
    }
    if lowered.starts_with('!') || lowered.chars().any(char::is_whitespace) {
        return ["hol-guard", "plugin-guard"]
            .iter()
            .any(|needle| lowered.contains(needle));
    }
    components.windows(2).any(|pair| {
        let stem = PROGRAM_SUFFIXES
            .iter()
            .find_map(|suffix| pair[1].strip_suffix(suffix))
            .unwrap_or(pair[1]);
        INSTALL_PARENTS.contains(&pair[0]) && GUARD_PROGRAMS.contains(&stem)
    })
}

/// Whether text names Guard's state directory or the variable that moves it.
/// Holds for every argument, whatever reads it.
pub(super) fn names_guard_state(argument: &str) -> bool {
    let lowered = argument.to_ascii_lowercase().replace('\\', "/");
    [".hol-guard", ".plugin-guard", "hol_guard_home"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

/// A network remote: `https://`, `ssh://` or `git://` URL, or the scp-like
/// `user@host:path` form. A `file://` URL and a bare path are local.
fn remote_url(lowered: &str) -> bool {
    if let Some((scheme, rest)) = lowered.split_once("://") {
        return matches!(
            scheme,
            "http" | "https" | "ssh" | "git" | "git+ssh" | "ssh+git"
        ) && rest.split('/').next().is_some_and(|host| !host.is_empty());
    }
    let Some((host, _)) = lowered.split_once(':') else {
        return false;
    };
    // `C:/x` is a drive and `./a:b` a path; a remote host has a dot or a user.
    !host.is_empty()
        && !host.contains('/')
        && (host.contains('@') || host.contains('.'))
        && !host.starts_with('.')
        && !host.starts_with('-')
}

/// The values `gh api` sends with `-f`/`--raw-field`. A raw field is a
/// string in the request, never a file Guard's host reads, so only the state
/// screen applies to it. A field that follows a flag which could take it as
/// that flag's value does not count.
pub(super) fn github_api_raw_fields(segment: &crate::CommandSegmentV1) -> Vec<&String> {
    let arguments = &segment.arguments;
    let mut values = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "--" {
            break;
        }
        if argument.starts_with("--raw-field=") {
            if index == 0 || !super::takes_next_value(&arguments[index - 1], false) {
                values.push(argument);
            }
            continue;
        }
        if index == 0 || !matches!(arguments[index - 1].as_str(), "-f" | "--raw-field") {
            continue;
        }
        if index >= 2 && super::takes_next_value(&arguments[index - 2], false) {
            continue;
        }
        values.push(argument);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkouts_pathspecs_and_remotes_named_after_guard_are_not_guard() {
        for argument in [
            "/home/u/projects/hol-guard-pr-12",
            "/home/u/projects/org/hol-guard",
            "../hol-guard",
            "hol-guard",
            "scripts/win/hol-guard.wxs",
            "/tmp/x/hol-guard-contrast",
            "https://github.com/someone/hol-guard.git",
            "git@github.com:someone/hol-guard.git",
            "ssh://git@github.com/someone/hol-guard.git",
            "C:\\Users\\u\\src\\hol-guard",
            "origin/fix/hol-guard-names",
        ] {
            assert!(!names_guard_location(argument), "{argument}");
        }
    }

    #[test]
    fn guard_state_programs_and_installs_are_guard() {
        for argument in [
            "~/.hol-guard",
            "/home/u/.hol-guard/guard.db",
            "$HOL_GUARD_HOME/x",
            "~/.local/pipx/venvs/hol-guard",
            "/home/u/.local/share/uv/tools/hol-guard/bin",
            "~/.local/bin/hol-guard",
            "/opt/homebrew/Cellar/hol-guard",
            "C:\\Program Files\\HOL Guard\\hol-guard.exe",
            "/Applications/HOL Guard.app",
            "/usr/local/bin/plugin-guard",
            "venv/lib/python3.12/site-packages/hol_guard",
            "file:///home/u/.hol-guard",
            "!hol-guard hooks remove",
            "hol-guard uninstall",
        ] {
            assert!(names_guard_location(argument), "{argument}");
        }
    }

    #[test]
    fn only_network_remotes_are_remote() {
        assert!(remote_url("https://github.com/o/r.git"));
        assert!(remote_url("git@github.com:o/r.git"));
        assert!(!remote_url("file:///tmp/r"));
        assert!(!remote_url("c:/users/u"));
        assert!(!remote_url("./a:b"));
        assert!(!remote_url("https:///x"));
        assert!(!remote_url("refs/heads/main:refs/heads/x"));
    }
}
