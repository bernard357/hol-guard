use super::*;
use std::fs;
use std::path::PathBuf;

fn scope_named(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-lifecycle-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    fs::create_dir(&scope).unwrap();
    scope
}

fn stored(scope: &Path) -> Journal {
    let encoded = fs::read(scope.join(JOURNAL_FILE)).unwrap();
    serde_json::from_slice(&encoded).unwrap()
}

#[test]
fn an_install_with_no_history_reports_nothing_rather_than_a_healthy_day() {
    let scope = scope_named("empty");

    assert!(health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_day_of_runs_reads_back_as_counts() {
    let scope = scope_named("counts");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);
    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "healthy");
    assert_eq!(health.starts, 2);
    assert_eq!(health.orderly_exits, 2);
    assert_eq!(health.failed_exits, 0);
    assert_eq!(health.last_event, "exited_orderly");
    assert!(health.last_event_age_seconds < 60);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_refused_start_is_the_state_that_says_nothing_took_its_place() {
    let scope = scope_named("refused");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::StartRefused);

    assert_eq!(health(&scope).unwrap().unwrap().state, "critical");

    // A start that succeeds after the circuit closes is no longer critical,
    // but the day it happened in is still not a healthy one.
    record(&scope, Event::Started);
    assert_eq!(health(&scope).unwrap().unwrap().state, "degraded");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_crash_earlier_in_the_day_is_not_erased_by_a_good_run_after_it() {
    let scope = scope_named("degraded");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "degraded");
    assert_eq!(health.failed_exits, 1);
    assert_eq!(health.orderly_exits, 1);
    assert_eq!(health.last_event, "exited_orderly");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_run_that_reports_success_too_early_is_counted_apart_from_a_healthy_one() {
    let scope = scope_named("premature");

    record(&scope, Event::ExitedPremature);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "degraded");
    assert_eq!(health.premature_exits, 1);
    assert_eq!(health.orderly_exits, 0);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn the_journal_holds_nothing_but_counts_and_this_module_s_own_vocabulary() {
    // The scope path carries something a support bundle must never repeat, so
    // a journal that reached for its surroundings would be caught here.
    let scope = scope_named("private-home-of-a-person-s3cr3t");

    for event in [
        Event::Started,
        Event::ExitedOrderly,
        Event::ExitedFailed,
        Event::ExitedPremature,
        Event::StartRefused,
    ] {
        record(&scope, event);
    }

    let encoded = fs::read(scope.join(JOURNAL_FILE)).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(!text.contains("private-home"), "{text}");

    let allowed_keys = [
        "schema",
        "window_start_ms",
        "starts",
        "orderly_exits",
        "failed_exits",
        "premature_exits",
        "refused_starts",
        "last_event",
        "last_event_ms",
    ];
    let allowed_strings = [
        JOURNAL_SCHEMA,
        Event::Started.code(),
        Event::ExitedOrderly.code(),
        Event::ExitedFailed.code(),
        Event::ExitedPremature.code(),
        Event::StartRefused.code(),
    ];
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let object = value.as_object().unwrap();
    for (key, field) in object {
        assert!(allowed_keys.contains(&key.as_str()), "{key}");
        match field {
            serde_json::Value::Number(_) => {}
            serde_json::Value::String(text) => {
                assert!(allowed_strings.contains(&text.as_str()), "{text}");
            }
            other => panic!("unexpected journal value {other}"),
        }
    }
    assert_eq!(object.len(), allowed_keys.len());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn yesterday_s_failures_stop_being_reported_once_the_window_closes() {
    let scope = scope_named("window");
    let now = now_ms().unwrap();
    let yesterday = now - JOURNAL_WINDOW_MS;

    record_at(&scope, Event::ExitedFailed, Some(yesterday)).unwrap();
    assert_eq!(stored(&scope).failed_exits, 1);

    // The next event opens a fresh window rather than adding to a day that
    // has already closed.
    record_at(&scope, Event::Started, Some(now)).unwrap();
    let journal = stored(&scope);
    assert_eq!(journal.failed_exits, 0);
    assert_eq!(journal.starts, 1);
    assert_eq!(journal.window_start_ms, now);
    assert_eq!(health_state(&journal), "healthy");

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_journal_left_behind_by_a_window_that_closed_is_not_reported_as_today() {
    let scope = scope_named("stale");
    let stale = now_ms().unwrap() - JOURNAL_WINDOW_MS;

    record_at(&scope, Event::ExitedFailed, Some(stale)).unwrap();

    assert!(health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_damaged_journal_costs_its_own_day_and_nothing_else() {
    let scope = scope_named("damaged");

    record(&scope, Event::Started);
    fs::write(scope.join(JOURNAL_FILE), b"{\"schema\":\"something else\"}").unwrap();

    record(&scope, Event::ExitedOrderly);

    let health = health(&scope).unwrap().unwrap();
    assert_eq!(health.state, "healthy");
    assert_eq!(health.starts, 0);
    assert_eq!(health.orderly_exits, 1);

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_journal_that_cannot_be_written_does_not_make_a_caller_fail() {
    // `record` is called from paths whose answer the runtime has already
    // decided, so a journal it cannot write has to be dropped in silence.
    let scope = scope_named("unwritable");
    // A directory standing where the file belongs fails every write without
    // needing a permission the test suite may itself be running as root over.
    fs::create_dir(scope.join(JOURNAL_FILE)).unwrap();

    record(&scope, Event::Started);

    assert!(health(&scope).is_err() || health(&scope).unwrap().is_none());

    fs::remove_dir_all(scope).unwrap();
}

#[test]
fn every_event_has_its_own_counter() {
    let scope = scope_named("distinct");

    record(&scope, Event::Started);
    record(&scope, Event::ExitedOrderly);
    record(&scope, Event::ExitedFailed);
    record(&scope, Event::ExitedPremature);
    record(&scope, Event::StartRefused);

    let journal = stored(&scope);
    assert_eq!(
        (
            journal.starts,
            journal.orderly_exits,
            journal.failed_exits,
            journal.premature_exits,
            journal.refused_starts,
        ),
        (1, 1, 1, 1, 1)
    );

    fs::remove_dir_all(scope).unwrap();
}
