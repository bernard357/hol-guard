#![forbid(unsafe_code)]

//! Bring this runtime's resident up before a session's first hook needs it.
//!
//! A cold resident costs the first interactive hook of a session the whole
//! start: the spawn, the startup lock, the catalog and the policy. The
//! session-start lane runs this once per session, detached, so that start
//! happens while the user is still reading their prompt.
//!
//! The request is the resident's own `health` operation, which answers from
//! the running process and decides nothing. Nothing here produces a verdict,
//! a receipt or an approval, and a prewarm that fails leaves the first hook
//! exactly where it was before.
//!
//! An ownerless resident retires once no client has held a lease for
//! `LEASE_EXPIRY` (`spawn_owner_lease_watcher`), so starting one and exiting
//! would retire it about a second later. The prewarm instead holds its own
//! client lease for a bounded window and then lets go: a session whose first
//! hook arrives inside the window finds the resident up and takes its own
//! lease, and a session that never uses a hook leaves nothing running.
//!
//! A resident some other client is already holding is left alone: the
//! prewarm returns before it takes a lease of its own.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::resident_process_identity::executable_missing;
use crate::resident_state::runtime_digest;

/// The resident operation this asks for: it answers from the running
/// process, so it measures the start and nothing else.
const PREWARM_PAYLOAD: &[u8] = br#"{"operation":"health","request":{}}"#;
/// Budget for the start and the health answer together, above the client's
/// own 9 second start timeout so a slow start is still waited out.
const PREWARM_REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
/// How long the prewarm keeps a resident it started alive. Long enough for
/// the first tool call of a session, short enough that an unused session
/// leaves no resident behind.
const PREWARM_HOLD: Duration = Duration::from_secs(120);
/// How often the hold rechecks that this runtime is still installed.
const PREWARM_POLL: Duration = Duration::from_millis(250);

pub(super) fn run(state_base: &Path) -> Result<(), String> {
    run_with_hold(state_base, PREWARM_HOLD)
}

pub(super) fn run_with_hold(state_base: &Path, hold: Duration) -> Result<(), String> {
    let digest = runtime_digest()?;
    if super::lease::any_live(state_base, &digest) {
        return Ok(());
    }
    let client_lease = super::lease::acquire(state_base)?;
    super::client_request_with_lease(
        state_base,
        PREWARM_PAYLOAD,
        PREWARM_REQUEST_TIMEOUT,
        &client_lease,
    )?;
    hold_lease(hold, std::env::current_exe().ok().as_deref());
    Ok(())
}

/// Hold the lease for `window`, ending early when `executable` is no longer
/// installed, so an upgrade does not keep the replaced resident alive. An
/// unknown executable only means this cannot watch for the upgrade; the
/// window still bounds the hold.
fn hold_lease(window: Duration, executable: Option<&Path>) {
    let deadline = Instant::now() + window;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        if executable.is_some_and(executable_missing) {
            return;
        }
        thread::sleep(left.min(PREWARM_POLL));
    }
}

#[cfg(all(test, unix))]
#[path = "managed_resident_prewarm_tests.rs"]
mod tests;
