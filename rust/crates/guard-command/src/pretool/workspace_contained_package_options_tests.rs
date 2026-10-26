use super::skip_inert_options;

/// The words a manager reads before its verb are skipped, so the verb behind
/// them is the one the admission check reads.
#[test]
fn an_inert_option_does_not_hide_the_verb() {
    for (manager, arguments, verb) in [
        ("pnpm", vec!["--silent", "build"], "build"),
        ("pnpm", vec!["-r", "build"], "build"),
        ("pnpm", vec!["--reporter", "silent", "test"], "test"),
        ("pnpm", vec!["--reporter=silent", "test"], "test"),
        ("pnpm", vec!["--filter", "web", "build"], "build"),
        ("pnpm", vec!["-F", "@acme/web", "lint"], "lint"),
        ("npm", vec!["--silent", "run", "build"], "run"),
        ("npm", vec!["--loglevel=error", "test"], "test"),
        ("npm", vec!["--workspace", "web", "run", "build"], "run"),
        ("yarn", vec!["--silent", "build"], "build"),
        ("bun", vec!["--bun", "run", "build"], "run"),
    ] {
        let skipped = skip_inert_options(manager, &arguments);
        assert_eq!(arguments.get(skipped).copied(), Some(verb), "{arguments:?}");
    }
}

/// An option the lists do not hold stops the walk where it stands, so the
/// verb stays hidden and the command keeps the admission it has today.
#[test]
fn an_unknown_option_still_hides_the_verb() {
    for (manager, arguments) in [
        // A bare `yarn` installs, and so does one carrying only options.
        ("yarn", vec!["--frozen-lockfile"]),
        ("npm", vec!["--prefix", "web", "run", "build"]),
        ("pnpm", vec!["-C", "web", "build"]),
        ("bun", vec!["--cwd", "web", "run", "build"]),
        ("pnpm", vec!["--registry", "https://example.test", "build"]),
        // Each list is its own manager's; bun reads none of pnpm's.
        ("bun", vec!["-r", "build"]),
    ] {
        let skipped = skip_inert_options(manager, &arguments);
        assert!(
            arguments
                .get(skipped)
                .is_none_or(|argument| argument.starts_with('-')),
            "{arguments:?}"
        );
    }
}

/// A selector naming a directory is refused, so a filter cannot reach a
/// project the workspace does not hold.
#[test]
fn a_path_selector_is_not_an_inert_value() {
    for arguments in [
        vec!["--filter", "./packages/web", "build"],
        vec!["--filter", "../sibling", "build"],
        vec!["--filter=./packages/web", "build"],
        vec!["--filter", "/opt/other", "build"],
        vec!["--filter", "~/other", "build"],
        vec!["--filter", "web/../../other", "build"],
        vec!["--filter", "..\\other", "build"],
        // A missing value leaves the option itself in front of the verb.
        vec!["--filter"],
        vec!["--filter", "--silent", "build"],
    ] {
        assert_eq!(skip_inert_options("pnpm", &arguments), 0, "{arguments:?}");
    }
}

/// A scoped package name is a name, not a path.
#[test]
fn a_scoped_name_is_an_inert_value() {
    assert_eq!(
        skip_inert_options("pnpm", &["--filter", "@acme/web", "build"]),
        2
    );
}
