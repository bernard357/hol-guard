use super::*;

#[test]
fn only_quoted_parameters_that_root_a_path_pass() {
    for text in [
        "find \"$HOME/Downloads/x\" -type f -exec basename {} \\;",
        "find \"${HOME}/src\" -exec basename {} \\; && shasum \"$HOME/x\"/*",
        "find src -name '$x' -exec basename {} \\;",
        "find src -exec basename {} \\;",
    ] {
        assert!(parameters_only_root_paths(text), "{text}");
    }
    for text in [
        "find $HOME/x -exec basename {} \\;",
        "find \"$HOME\" -exec basename {} \\;",
        "find \"$(pwd)/x\" -exec basename {} \\;",
        "find \"$1/x\" -exec basename {} \\;",
        "find \"${HOME:-/}/x\" -exec basename {} \\;",
        "find \"$HOME/x\" -exec basename {} \\; $'\\x41'",
        "find \"$HOME/x -exec basename {} \\;",
    ] {
        assert!(!parameters_only_root_paths(text), "{text}");
    }
}

#[test]
fn only_plain_lowercase_shell_variables_are_set_aside() {
    for word in ["nodepath=/x", "dir=\"$HOME/x\"", "widgets_dir=a"] {
        assert!(binds_a_shell_variable(word), "{word}");
    }
    for word in [
        "PATH=/tmp",
        "path=/tmp",
        "fpath=/tmp",
        "NODE_OPTIONS=--require=x",
        "node_options=--require=x",
        "http_proxy=http://x",
        "api_token=x",
        "ROOT=/x",
    ] {
        assert!(!binds_a_shell_variable(word), "{word}");
    }
}

#[test]
fn a_loop_piece_is_split_outside_quotes_and_past_its_assignments() {
    assert_eq!(
        split_unquoted("do node -e 'a(1); b()' \"$f\"; done", |c| c == ';'),
        Some(vec!["do node -e 'a(1); b()' \"$f\"", " done"])
    );
    assert_eq!(split_unquoted("node -e 'open", |c| c == ';'), None);
    assert!(!changes_directory("nodepath=\"$HOME/a b\""));
    assert!(changes_directory("dir=\"a b\" cd /tmp"));
    assert!(changes_directory("pushd /tmp"));
    assert!(changes_directory("$step /tmp"));
}
