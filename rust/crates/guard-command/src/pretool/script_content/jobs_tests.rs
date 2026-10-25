use super::{background_moves_shell, sequential_jobs};

#[test]
fn a_job_followed_by_a_command_reads_as_a_list() {
    assert_eq!(
        sequential_jobs("node server.js & echo started").as_deref(),
        Some("node server.js ; echo started")
    );
    assert_eq!(
        sequential_jobs("python3 app.py & sleep 2 && echo ready").as_deref(),
        Some("python3 app.py ; sleep 2 && echo ready")
    );
}

#[test]
fn a_trailing_job_drops_its_ampersand() {
    assert_eq!(
        sequential_jobs("node server.js &").as_deref(),
        Some("node server.js")
    );
}

#[test]
fn lists_redirects_and_quotes_keep_their_ampersands() {
    assert_eq!(sequential_jobs("make && make test"), None);
    assert_eq!(sequential_jobs("echo 'a & b'"), None);
    // A redirect is outside what the split reads, so the text stays uncertain
    // rather than losing the `&` of `2>&1`.
    assert_eq!(
        sequential_jobs("node server.js > out.log 2>&1 & echo started"),
        None
    );
}

#[test]
fn a_background_job_that_moves_the_shell_stays_uncertain() {
    assert!(background_moves_shell("cd app && npm start & ls"));
    assert!(background_moves_shell("PORT=1 & node server.js"));
    assert!(background_moves_shell("export PORT=1 & node server.js"));
    // The last job moves nothing the shell runs afterwards.
    assert!(!background_moves_shell("node server.js & cd app"));
    assert!(!background_moves_shell("cd app && node server.js &"));
    assert!(!background_moves_shell(
        "node server.js --port=3000 & echo started"
    ));
}
