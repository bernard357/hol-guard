//! Check one signed network protection bundle response for a caller that
//! holds no verifier.
//!
//! [`guard_command::network_protection_bundle`] owns the decision. This
//! operation only reads the caller's response and saved keyring onto that
//! module's types and reports what it answered, so the only network
//! protection bundle verifier in the product is the one here. On success it
//! returns the saved form, because the caller must not rebuild it: the
//! expiry epoch and payload hash it writes are the verifier's own.

use guard_command::network_protection_bundle::{
    verify_network_protection_response, NetworkProtectionBundleError,
};
use guard_command::supply_chain_bundle::{
    load_supply_chain_verification_keys, RingRsaPssVerify, SupplyChainVerificationKey,
};
use guard_contracts::{
    NetworkProtectionVerifyRequestV1, NetworkProtectionVerifyResultV1, MAX_NATIVE_REQUEST_BYTES,
    NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_network_protection_verify_request(
    request: &NetworkProtectionVerifyRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, MAX_NATIVE_REQUEST_BYTES)
        .map_err(|_| "native_network_protection_verify_too_large".to_owned())?;

    let payload = match verify(request) {
        Ok(saved) => json!({ "outcome": "verified", "saved": saved }),
        Err(error) => json!({ "outcome": "refused", "message": error.to_string() }),
    };

    crate::encode_response(&NetworkProtectionVerifyResultV1 {
        schema: NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload,
    })
}

fn verify(
    request: &NetworkProtectionVerifyRequestV1,
) -> Result<Value, NetworkProtectionBundleError> {
    let trusted = trusted_keys(request.trusted_keys.as_ref())?;
    verify_network_protection_response(
        &request.response,
        &request.workspace_id,
        &trusted,
        request.cached_bundle_version.as_deref(),
        request.now,
        &RingRsaPssVerify,
    )
}

/// A keyring the resident cannot read is not an empty keyring, so a malformed
/// one refuses the bundle rather than silently falling back to the pinned
/// fingerprint, as the Python caller did when its keyring failed to load.
fn trusted_keys(
    raw: Option<&Value>,
) -> Result<Vec<SupplyChainVerificationKey>, NetworkProtectionBundleError> {
    load_supply_chain_verification_keys(raw)
        .map_err(|error| NetworkProtectionBundleError(error.to_string()))
}

#[cfg(test)]
#[path = "network_protection_verify_op_tests.rs"]
mod tests;
