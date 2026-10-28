//! The contained grant, answered in the direct lane.
//!
//! A reviewed `PreToolUse` the edge routes to the grant
//! (`containment_route` is `grant`) is an outside-roots review a local CLI
//! grant on this device may widen the workspace sandbox for. The daemon asks
//! for that grant before it pauses the call for approval, and an allowed
//! grant runs the call in the widened sandbox instead. The direct lane runs
//! the edge's own grant step with the daemon's rules before it reads a saved
//! decision: the store under the request's Guard home, and the home and
//! environment the direct lane shares with the daemon it runs inside.
//!
//! A routed call runs Guard's sink with the request snapshot the rewrite
//! wrote; a receipt-only call gets the granted receipt. A call no grant
//! routes keeps its review for the saved-decision read. A grant step that
//! fails or runs out of time defers, and so does a Claude Code or ZCode call
//! whose binding carries no sink command, so the daemon asks for the grant.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use guard_contracts::{GuardHookLocalCliRulesV1, GuardHookSourceMetadataV2};
use serde_json::{Map, Value};

use super::contained::Snapshot;
use super::{reviewed_edge, HookDirectDefer, PRE_TOOL_USE};
use crate::edge::edge_containment::grant::{granted, GrantRequest, Granted};
use crate::local_store_read::STORE_FILE_NAME;

const GRANT_ROUTE: &str = "grant";

/// The edge answer the grant answered, and the request snapshot it runs.
pub(super) type Answered = (Value, Option<Snapshot>);

/// A reviewed `PreToolUse` and where the grant step reads it.
pub(super) struct GrantCall<'a> {
    pub(super) harness: &'a str,
    pub(super) payload: &'a Map<String, Value>,
    pub(super) source: &'a GuardHookSourceMetadataV2,
    /// Whether the harness applies `updatedInput`, so the daemon would route
    /// the granted call with the sink command it binds.
    pub(super) contained: bool,
    pub(super) sink_command: Option<&'a [String]>,
    pub(super) deadline: Instant,
}

/// The edge answer with the grant's response in place of its review, and the
/// request snapshot a routed call runs; `None` when the edge did not route
/// the call to the grant or no grant routes it, so the review stands.
pub(super) fn answer(
    edge: &[u8],
    call: &GrantCall<'_>,
) -> Result<Option<Answered>, HookDirectDefer> {
    let answered = reviewed_edge(edge, PRE_TOOL_USE)?;
    if answered.get("containment_route").and_then(Value::as_str) != Some(GRANT_ROUTE) {
        return Ok(None);
    }
    granted_answer(answered, call, &daemon_rules(&call.source.guard_home)?)
}

/// `answer` for a grant-routed edge answer, read with `rules`.
fn granted_answer(
    mut answered: Value,
    call: &GrantCall<'_>,
    rules: &GuardHookLocalCliRulesV1,
) -> Result<Option<Answered>, HookDirectDefer> {
    let sink_command = match call.sink_command {
        Some(command) => command,
        None if call.contained => return Err(HookDirectDefer::ContainedRouteFailed),
        // Any other harness is never rewritten, so no sink is read.
        None => &[],
    };
    let request = GrantRequest {
        harness: call.harness,
        payload: call.payload,
        result: &answered["result"],
        source: call.source,
        rules,
        sink_command,
        deadline: call.deadline,
    };
    let (response, snapshot) = match granted(&request) {
        Some(Granted::Routed(routed)) => {
            let snapshot = Snapshot::of_routed(&routed);
            (routed, snapshot)
        }
        Some(Granted::Kept(receipt)) => (receipt, None),
        Some(Granted::Declined) => return Ok(None),
        None => return Err(HookDirectDefer::ContainedRouteFailed),
    };
    answered["harness_response"] = response;
    Ok(Some((answered, snapshot)))
}

/// The rules the daemon sends the edge's grant step: its store, home and
/// environment, which the direct lane shares.
fn daemon_rules(guard_home: &str) -> Result<GuardHookLocalCliRulesV1, HookDirectDefer> {
    let user_home = std::env::var("HOME").map_err(|_| HookDirectDefer::ContainedRouteFailed)?;
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    Ok(GuardHookLocalCliRulesV1 {
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        user_home,
        env,
        exact_action_control_digest: None,
    })
}

#[cfg(all(test, unix))]
#[path = "hook_direct_grant_tests.rs"]
mod tests;
