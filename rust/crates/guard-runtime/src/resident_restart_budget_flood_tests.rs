//! A failing resident must not become one process per failure.
//!
//! Every spawn is charged against the restart budget before the process is
//! created, so the bound these tests prove is a bound on processes: a grant is
//! a resident, a refusal is not. The three shapes a crash loop actually takes
//! are a tight retry loop, a loop patient enough to wait out each backoff, and
//! a burst of clients that all miss the resident at once.

use super::*;
use std::path::PathBuf;
use std::sync::mpsc;

/// Bring the open circuit's deadline into the past without moving the window,
/// which is what waiting for the backoff does to a real caller. The window is
/// left alone so the ladder is measured on its own rather than being reset
/// partway through by a minute going by.
fn elapse_circuit(scope: &Path) {
    let private_root = crate::resident_state::private_root_for_scope(scope).unwrap();
    let mut budget: RestartBudget =
        serde_json::from_slice(&std::fs::read(scope.join("restart-budget.json")).unwrap()).unwrap();
    budget.circuit_until_ms = now_ms().unwrap().saturating_sub(1);
    write_private(
        &scope.join("restart-budget.json"),
        &serde_json::to_vec(&budget).unwrap(),
        &private_root,
    )
    .unwrap();
}

fn budget_of(scope: &Path) -> RestartBudget {
    serde_json::from_slice(&std::fs::read(scope.join("restart-budget.json")).unwrap()).unwrap()
}

fn flood_scope(label: &str) -> PathBuf {
    let scope = std::env::temp_dir().join(format!(
        "hol-guard-restart-flood-{label}-{}-{}",
        std::process::id(),
        now_ms().unwrap()
    ));
    std::fs::create_dir(&scope).unwrap();
    scope
}

#[test]
fn sixty_four_failures_in_a_row_start_three_residents() {
    let scope = flood_scope("tight");

    let mut granted = 0usize;
    for _ in 0..64 {
        match consume(&scope) {
            Ok(()) => granted += 1,
            Err(error) => assert_eq!(error, "native_resident_restart_circuit_open"),
        }
    }

    assert_eq!(granted, MAX_RESTARTS_PER_WINDOW as usize);
    // Retrying faster buys nothing back. A refusal while the circuit is open
    // returns before it reaches the backoff, so the sixty refusals after the
    // first one leave the same single step behind that the first one set.
    assert_eq!(budget_of(&scope).backoff_steps, 1);

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn a_loop_patient_enough_to_wait_out_every_backoff_still_pays_for_each_resident() {
    let scope = flood_scope("patient");

    let mut granted = 0usize;
    let mut waited_ms = 0u64;
    for _ in 0..64 {
        match consume(&scope) {
            Ok(()) => granted += 1,
            Err(error) => {
                assert_eq!(error, "native_resident_restart_circuit_open");
                // The refusal names the moment the next spawn becomes
                // possible. A caller cannot reach it any sooner than by
                // waiting, so the step it just set is time this loop owes.
                waited_ms = waited_ms.saturating_add(backoff_ms(
                    budget_of(&scope).backoff_steps.saturating_sub(1),
                ));
                elapse_circuit(&scope);
            }
        }
    }

    // Past the free restarts every resident costs one elapsed backoff, so the
    // loop alternates and the sixty-four failures cannot all be served.
    assert!(granted < 64, "granted {granted} residents for 64 failures");
    // Those residents are spread over hours of enforced waiting rather than
    // arriving at once, which is the property that keeps a crash loop from
    // behaving like a fork bomb.
    assert!(
        waited_ms >= 10 * 60_000,
        "64 failures demanded only {waited_ms}ms of waiting"
    );
    assert_eq!(budget_of(&scope).backoff_steps as usize, 64 - granted);

    std::fs::remove_dir_all(scope).unwrap();
}

#[test]
fn sixty_four_clients_that_all_miss_the_resident_at_once_do_not_each_start_one() {
    let scope = flood_scope("burst");

    let (results, collect) = mpsc::channel();
    let threads: Vec<_> = (0..64)
        .map(|_| {
            let scope = scope.clone();
            let results = results.clone();
            std::thread::spawn(move || results.send(consume(&scope)).unwrap())
        })
        .collect();
    drop(results);
    let outcomes: Vec<_> = collect.iter().collect();
    for thread in threads {
        thread.join().unwrap();
    }

    assert_eq!(outcomes.len(), 64);
    let granted = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    // The budget is taken under an exclusive lock, so a burst is charged one
    // at a time however many clients arrive together.
    assert!(
        granted <= MAX_RESTARTS_PER_WINDOW as usize,
        "a burst of 64 started {granted} residents"
    );
    for outcome in &outcomes {
        if let Err(error) = outcome {
            // A client that could not take the lock in time is refused too.
            // Either way it did not start a resident.
            assert!(
                matches!(
                    error.as_str(),
                    "native_resident_restart_circuit_open" | "native_resident_restart_budget_busy"
                ),
                "unexpected refusal {error}"
            );
        }
    }

    std::fs::remove_dir_all(scope).unwrap();
}
