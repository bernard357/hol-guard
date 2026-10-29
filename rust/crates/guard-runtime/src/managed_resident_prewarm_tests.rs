use super::*;

use std::fs;
use std::path::PathBuf;

fn test_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hol-guard-managed-prewarm-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    fs::create_dir(&directory).expect("test directory should be creatable");
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("test directory should be private");
    directory
}

#[test]
fn the_prewarm_asks_the_resident_for_its_health() {
    let value = crate::strict_json_value(PREWARM_PAYLOAD).expect("the payload should be a request");
    let operation =
        crate::strict_json::from_value::<crate::resident_protocol::ResidentOperationV1>(value)
            .expect("the resident should answer the operation the prewarm sends");
    assert!(
        matches!(
            operation,
            crate::resident_protocol::ResidentOperationV1::Health(_)
        ),
        "the prewarm asks for health, which decides nothing: {operation:?}"
    );
}

#[test]
fn a_client_already_holding_a_lease_keeps_the_prewarm_out() {
    let state_base = test_directory("held");
    let held = super::super::lease::acquire(&state_base).expect("the test should hold a lease");
    let started = Instant::now();
    run_with_hold(&state_base, Duration::from_secs(600)).expect("a held resident is a warm one");
    assert!(
        started.elapsed() < PREWARM_HOLD,
        "the prewarm returned before taking a lease or a hold of its own"
    );
    drop(held);
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn the_hold_ends_when_its_window_closes() {
    let window = Duration::from_millis(120);
    let executable = std::env::current_exe().expect("the test binary should be on disk");
    let started = Instant::now();
    hold_lease(window, Some(&executable));
    assert!(
        started.elapsed() >= window,
        "the hold served its whole window"
    );
}

#[test]
fn the_hold_ends_when_this_runtime_is_replaced() {
    let state_base = test_directory("replaced");
    let missing = state_base.join("hol-guard-runtime");
    let started = Instant::now();
    hold_lease(Duration::from_secs(600), Some(&missing));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "an uninstalled runtime ends the hold instead of keeping the replaced resident alive"
    );
    let _ = fs::remove_dir_all(&state_base);
}

#[test]
fn an_unknown_executable_still_serves_the_window() {
    let window = Duration::from_millis(120);
    let started = Instant::now();
    hold_lease(window, None);
    assert!(
        started.elapsed() >= window,
        "an unknown executable bounds nothing but the upgrade watch"
    );
}
