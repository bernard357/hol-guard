//! The edge records its own decision receipt.
//!
//! The daemon used to submit every edge answer's receipt to the hook evidence
//! writer in a second resident request. When the envelope asks for it, the
//! edge queues the receipt with the writer itself and says so in its answer,
//! so the daemon skips that request.
//!
//! Only a writer already running for the request's Guard home takes the
//! receipt: starting one replays its journal, which no hook answer waits for.
//! Without a running writer the answer says nothing was recorded and the
//! daemon submits the receipt as before, which starts the writer. The receipt
//! is queued only once the answer is encoded, so a call that fails closed on
//! an answer too large to send leaves no receipt behind. It is queued before
//! the answer leaves, so it precedes the command activity that links to it.

use std::path::Path;
use std::time::Instant;

use guard_contracts::{GuardHookEdgeResultV2, GuardHookEnvelopeV2};

use crate::hook_evidence_writer_op as writer_op;

/// The resident feature under which an envelope may ask for this.
pub(crate) const EDGE_RECEIPT_RECORD_FEATURE: &str = "edge-receipt-record-v1";

/// Encode the checked `edge`, recording its receipt when the envelope asked
/// and a writer runs for its Guard home. `resident` is false for a caller
/// outside the resident's own edge request, which never records.
pub(crate) fn encode(
    envelope: &GuardHookEnvelopeV2,
    resident: bool,
    edge: GuardHookEdgeResultV2,
    started: Instant,
) -> Result<Vec<u8>, String> {
    let mut edge = crate::edge_structured::attached(envelope, edge, started);
    let writer_home = (resident && envelope.record_receipt)
        .then(|| writer_op::running_home(Path::new(&envelope.source.guard_home)))
        .flatten();
    edge.receipt_recorded = writer_home.is_some();
    let encoded = crate::encode_response(&edge)?;
    if let Some(guard_home) = writer_home {
        writer_op::queue_edge_receipt(&guard_home, &edge.receipt);
    }
    Ok(encoded)
}

#[cfg(test)]
#[path = "edge_receipt_tests.rs"]
mod tests;
