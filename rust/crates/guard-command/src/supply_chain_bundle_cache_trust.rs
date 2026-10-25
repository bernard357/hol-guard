//! Whether a stored supply-chain bundle response may still be used.
//!
//! Parsing a stored response is not proof that it is current. This checks the
//! paired workspace scope, the native signature, key state and freshness, and
//! that the recorded sync keyring still permits the signing key. Package
//! evaluation and runtime advisory matching share it so neither can accept a
//! bundle the other would refuse.

use std::fmt;

use serde_json::Value;

use crate::supply_chain_bundle::{
    load_supply_chain_verification_keys, verify_supply_chain_bundle_response, RingRsaPssVerify,
    SupplyChainBundle, SupplyChainBundleError, SupplyChainBundleResponse,
    BUNDLE_CLOCK_SKEW_SECONDS, BUNDLE_MAX_AGE_SECONDS,
};

/// Why a cached bundle cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CachedBundleRejection {
    /// The bundle or keyring belongs to another workspace, or the recorded
    /// keyring no longer permits the signing key.
    Scope(&'static str),
    /// The bundle itself failed verification.
    Bundle(SupplyChainBundleError),
}

impl fmt::Display for CachedBundleRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope(message) => f.write_str(message),
            Self::Bundle(error) => error.fmt(f),
        }
    }
}

impl From<SupplyChainBundleError> for CachedBundleRejection {
    fn from(error: SupplyChainBundleError) -> Self {
        Self::Bundle(error)
    }
}

/// `Ok(true)` when a matching recorded sync keyring anchored the signing key,
/// `Ok(false)` when the bundle verified against its own advertised keyring
/// only. The boolean is not a new trust root, and missing sync context can
/// never turn a rejection into a pass.
pub fn validate_cached_supply_chain_bundle(
    typed: &SupplyChainBundleResponse,
    workspace_id: &str,
    now: Option<f64>,
    sync_keyring: Option<&Value>,
    synced_bundle_version: Option<&str>,
) -> Result<bool, CachedBundleRejection> {
    if typed.bundle.workspace_id != workspace_id {
        return Err(CachedBundleRejection::Scope(
            "Cached bundle belongs to another workspace",
        ));
    }
    if sync_keyring.is_some_and(|payload| {
        payload.get("workspace_id").and_then(Value::as_str) != Some(workspace_id)
    }) {
        return Err(CachedBundleRejection::Scope(
            "Cached keyring belongs to another workspace",
        ));
    }
    let keys = load_supply_chain_verification_keys(sync_keyring)?;
    if sync_keyring.is_some() && keys.is_empty() {
        return Err(CachedBundleRejection::Scope("Cached sync keyring is empty"));
    }
    verify_supply_chain_bundle_response(
        typed,
        (!keys.is_empty()).then_some(keys.as_slice()),
        synced_bundle_version,
        now,
        &RingRsaPssVerify,
    )?;
    if !keys.is_empty() {
        let signer = typed
            .verification_keys
            .iter()
            .find(|key| key.key_id == typed.bundle.key_id)
            .ok_or(CachedBundleRejection::Scope(
                "Cached signing key is missing",
            ))?;
        // The response can advertise an old active key after the synced
        // keyring revoked it. Both views must permit the signing key.
        // The verifier already requires a matching fingerprint. Inspect
        // every matching entry so an active alias cannot hide revocation.
        for current in keys
            .iter()
            .filter(|key| key.fingerprint_sha256 == signer.fingerprint_sha256)
        {
            let usable = match current.state.as_str() {
                "active" => true,
                "grace" => {
                    let clock = now.or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|time| time.as_secs_f64())
                    });
                    let until = current.valid_until_timestamp()?;
                    matches!((clock, until), (Some(clock), Some(until)) if clock <= until)
                }
                _ => false,
            };
            if !usable {
                return Err(CachedBundleRejection::Scope(
                    "Synced signing key is not current",
                ));
            }
        }
    }
    Ok(!keys.is_empty())
}

/// The last moment the freshness check still accepts `bundle`: its signed
/// expiry or its maximum age, whichever comes first, with the clock skew the
/// check allows. A cached result built from the bundle is stale after it.
pub fn cached_supply_chain_bundle_valid_until(bundle: &SupplyChainBundle) -> Option<f64> {
    let expires = bundle.expires_at_timestamp().ok()? + BUNDLE_CLOCK_SKEW_SECONDS;
    let aged = bundle.generated_at_timestamp().ok()? + BUNDLE_MAX_AGE_SECONDS;
    Some(expires.min(aged))
}
