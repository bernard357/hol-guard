//! Process-wide counts of declarative command work, for scale measurement.
//!
//! Catalog-scale acceptance asks whether disabled entries change per-hook
//! work. These counters record the active extension set a resident compiled
//! and how many candidate rules the last declarative pass considered and ran.
//! They hold numbers only, never rule IDs or command text. The last pass is
//! kept per thread, because a resident request is evaluated and noted on the
//! same worker thread while other workers run their own requests.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_EXTENSIONS: AtomicUsize = AtomicUsize::new(0);
static MAX_CANDIDATES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static LAST_PASS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

/// The counts as of the most recent compile and declarative pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommandWorkStats {
    /// Extensions active in the most recently compiled controls.
    pub active_extensions: usize,
    /// Candidate rules the last declarative pass on this thread considered.
    pub last_candidates: usize,
    /// Candidates in that pass whose extension was active and whose matcher ran.
    pub last_evaluated: usize,
    /// The largest candidate count any pass in this process considered.
    pub max_candidates: usize,
}

pub fn snapshot() -> CommandWorkStats {
    let (last_candidates, last_evaluated) = LAST_PASS.with(Cell::get);
    CommandWorkStats {
        active_extensions: ACTIVE_EXTENSIONS.load(Ordering::Relaxed),
        last_candidates,
        last_evaluated,
        max_candidates: MAX_CANDIDATES.load(Ordering::Relaxed),
    }
}

pub(crate) fn record_active(count: usize) {
    ACTIVE_EXTENSIONS.store(count, Ordering::Relaxed);
}

pub(crate) fn record_pass(candidates: usize, evaluated: usize) {
    LAST_PASS.with(|last| last.set((candidates, evaluated)));
    MAX_CANDIDATES.fetch_max(candidates, Ordering::Relaxed);
}
