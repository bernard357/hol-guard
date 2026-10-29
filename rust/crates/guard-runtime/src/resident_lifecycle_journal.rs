//! What this install's managed resident has been doing lately, in counts.
//!
//! The failure log next door keeps the last unhealthy run's stderr so a person
//! can read why one run ended. That record is deliberately narrow: it is
//! overwritten by the next failure, it holds no record of the runs that
//! succeeded, and a one-shot client that spawns a resident and exits leaves no
//! trace of the attempt at all. Nothing in the runtime could therefore answer
//! the question a support request actually asks -- is this install's enforcement
//! healthy, or has it been failing all day?
//!
//! This journal answers that and nothing more. It holds a rolling day's counts
//! of starts, the three ways a run ends, and starts the restart budget refused,
//! plus a fixed code naming the last event and when it happened. There is no
//! path, no command, no process id, no stderr and no free text in it, so the
//! file can be read out to a user, or carried in a support bundle, without
//! anybody having to redact it first. The shape is fixed, so the file stays a
//! few hundred bytes however long the install runs.
//!
//! Every write is best effort. A journal is an observation of the runtime, not
//! a part of it: a busy lock, a full disk or a damaged file must never change
//! whether a resident spawns or how its exit is classified.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use super::private_file::recover_interrupted_replace;
use super::private_file::{read_private_bytes, write_private};

/// How much history one journal covers. A day is long enough that a user who
/// noticed something this morning can still see it this evening, and short
/// enough that an install which has since been repaired stops reporting the
/// failures it has recovered from.
const JOURNAL_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;
const JOURNAL_SCHEMA: &str = "hol-guard-resident-lifecycle-journal.v1";
const JOURNAL_FILE: &str = "lifecycle-journal.json";
const JOURNAL_LOCK_FILE: &str = "lifecycle-journal.lock";
/// A journal write is one small read and write under the lock, exactly like a
/// budget update, and it is taken on the exit path where a supervisor and a
/// spawning client can meet. Waiting briefly for an ordinary overlap costs
/// less than losing the event.
const JOURNAL_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const JOURNAL_LOCK_RETRIES: u32 = 20;

/// Something worth counting that happened to this install's resident.
///
/// This is the whole vocabulary of the journal. A caller cannot describe an
/// event in its own words, which is what keeps a path or a command out of the
/// file by construction rather than by review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// A spawn was charged and the resident was started.
    Started,
    /// A run ended the way a healthy one does.
    ExitedOrderly,
    /// A run ended reporting failure.
    ExitedFailed,
    /// A run reported success before it could have served anything.
    ExitedPremature,
    /// The restart budget refused a start because its circuit was open.
    StartRefused,
}

impl Event {
    /// The fixed code written to the file. These are the only strings this
    /// module ever stores beside its own schema.
    const fn code(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::ExitedOrderly => "exited_orderly",
            Self::ExitedFailed => "exited_failed",
            Self::ExitedPremature => "exited_premature",
            Self::StartRefused => "start_refused",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    window_start_ms: u64,
    starts: u32,
    orderly_exits: u32,
    failed_exits: u32,
    premature_exits: u32,
    refused_starts: u32,
    last_event: String,
    last_event_ms: u64,
}

impl Journal {
    fn new(now: u64) -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_owned(),
            window_start_ms: now,
            starts: 0,
            orderly_exits: 0,
            failed_exits: 0,
            premature_exits: 0,
            refused_starts: 0,
            last_event: String::new(),
            last_event_ms: 0,
        }
    }

    fn apply(&mut self, event: Event, now: u64) {
        let counter = match event {
            Event::Started => &mut self.starts,
            Event::ExitedOrderly => &mut self.orderly_exits,
            Event::ExitedFailed => &mut self.failed_exits,
            Event::ExitedPremature => &mut self.premature_exits,
            Event::StartRefused => &mut self.refused_starts,
        };
        // An install that somehow reaches four billion of anything inside a day
        // is already past the point where one more matters; it must not be the
        // thing that panics a supervisor on its way out.
        *counter = counter.saturating_add(1);
        self.last_event = event.code().to_owned();
        self.last_event_ms = now;
    }
}

/// What a reader is told about this install's recent lifecycle.
#[derive(Debug, Serialize)]
pub(crate) struct LifecycleHealth {
    /// `healthy`, `degraded` or `critical`, derived from the counts below.
    pub state: &'static str,
    pub starts: u32,
    pub orderly_exits: u32,
    pub failed_exits: u32,
    pub premature_exits: u32,
    pub refused_starts: u32,
    /// The fixed code of the most recent event, empty on a journal that has
    /// been created but never written to.
    pub last_event: String,
    /// How long ago the most recent event was, in seconds. Relative, so a
    /// published snapshot does not carry a wall-clock trail of the user's day.
    pub last_event_age_seconds: u64,
    pub window_age_seconds: u64,
}

/// How this install's day reads.
///
/// `critical` is the one state that says enforcement may be absent right now:
/// the last thing that happened was the restart budget refusing a start, so
/// the circuit is open and nothing started in its place.
///
/// `degraded` says the day contains runs that did not end healthily. That is
/// deliberately a property of the window rather than of the last event: an
/// install that crashes every few minutes and recovers in between is not
/// healthy, however good its most recent run looked.
fn health_state(journal: &Journal) -> &'static str {
    if journal.last_event == Event::StartRefused.code() {
        return "critical";
    }
    if journal.failed_exits > 0 || journal.premature_exits > 0 || journal.refused_starts > 0 {
        return "degraded";
    }
    "healthy"
}

struct JournalLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_journal_lock(scope: &Path, private_root: &Path) -> Result<JournalLock, String> {
    let path = scope.join(JOURNAL_LOCK_FILE);
    #[cfg(windows)]
    let (file, directory_binding) =
        crate::resident_state::private_lock_file(&path, private_root)
            .map_err(|_| "native_resident_lifecycle_journal_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, private_root)
        .map_err(|_| "native_resident_lifecycle_journal_lock_failed".to_owned())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            "native_resident_lifecycle_journal_busy".to_owned()
        } else {
            "native_resident_lifecycle_journal_lock_failed".to_owned()
        }
    })?;
    Ok(JournalLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

fn acquire_journal_lock_waiting(scope: &Path, private_root: &Path) -> Result<JournalLock, String> {
    let mut attempts = 0;
    loop {
        match acquire_journal_lock(scope, private_root) {
            Err(reason) if reason == "native_resident_lifecycle_journal_busy" => {
                attempts += 1;
                if attempts > JOURNAL_LOCK_RETRIES {
                    return Err(reason);
                }
                std::thread::sleep(JOURNAL_LOCK_RETRY_DELAY);
            }
            other => return other,
        }
    }
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "native_resident_clock_invalid".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "native_resident_clock_invalid".to_owned())
}

/// Read this scope's journal when it exists and is this module's own.
///
/// A file that fails to parse, or carries another schema, is treated as absent
/// rather than as an error to report: the journal is not authority, and the
/// next event rewrites it from a fresh window. Discarding one damaged day's
/// counts is cheaper than letting a corrupt file stop the runtime recording
/// anything ever again.
fn read_existing(path: &Path, private_root: &Path) -> Option<Journal> {
    let bytes = read_private_bytes(path, private_root, "lifecycle_journal").ok()??;
    let value = crate::strict_json_value(&bytes).ok()?;
    let journal = serde_json::from_value::<Journal>(value).ok()?;
    if journal.schema != JOURNAL_SCHEMA {
        return None;
    }
    Some(journal)
}

fn load_for_window(path: &Path, private_root: &Path, now: u64) -> Journal {
    match read_existing(path, private_root) {
        // A window that has closed is not this day, so its counts are not
        // this day's counts.
        Some(journal) if now.saturating_sub(journal.window_start_ms) < JOURNAL_WINDOW_MS => journal,
        _ => Journal::new(now),
    }
}

/// Count one event against this install's day.
///
/// Nothing is returned, and that is the point: every caller is on a path whose
/// result belongs to the runtime, not to the journal.
pub(super) fn record(scope: &Path, event: Event) {
    let _ = record_at(scope, event, None);
}

fn record_at(scope: &Path, event: Event, at_ms: Option<u64>) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_journal_lock_waiting(scope, &private_root)?;
    let path = scope.join(JOURNAL_FILE);
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let now = match at_ms {
        Some(simulated) => simulated,
        None => now_ms()?,
    };
    let mut journal = load_for_window(&path, &private_root, now);
    journal.apply(event, now);
    let encoded = serde_json::to_vec(&journal)
        .map_err(|_| "native_resident_lifecycle_journal_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

/// How this install's resident has been behaving, or `None` when it has no
/// journal yet. A read takes the lock so it cannot catch a half-written file
/// on a platform where the replace is not atomic.
pub(super) fn health(scope: &Path) -> Result<Option<LifecycleHealth>, String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_journal_lock_waiting(scope, &private_root)?;
    let path = scope.join(JOURNAL_FILE);
    let now = now_ms()?;
    let Some(journal) = read_existing(&path, &private_root) else {
        return Ok(None);
    };
    if now.saturating_sub(journal.window_start_ms) >= JOURNAL_WINDOW_MS {
        return Ok(None);
    }
    Ok(Some(LifecycleHealth {
        state: health_state(&journal),
        starts: journal.starts,
        orderly_exits: journal.orderly_exits,
        failed_exits: journal.failed_exits,
        premature_exits: journal.premature_exits,
        refused_starts: journal.refused_starts,
        last_event: journal.last_event.clone(),
        last_event_age_seconds: now.saturating_sub(journal.last_event_ms) / 1_000,
        window_age_seconds: now.saturating_sub(journal.window_start_ms) / 1_000,
    }))
}

#[cfg(test)]
#[path = "resident_lifecycle_journal_tests.rs"]
mod tests;
