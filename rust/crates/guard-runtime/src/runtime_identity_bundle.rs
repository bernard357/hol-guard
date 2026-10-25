//! Runtime advisories read from the cached, signed supply-chain bundle.
//!
//! The caller hands over the stored bundle response with its sync context;
//! nothing here reads the store. The bundle is accepted only when the shared
//! cached-bundle check passes (workspace scope, payload hash, signature, key
//! state, freshness and rollback), so a bundle with a bad signature, another
//! workspace's scope or an older version than the last sync never supplies
//! advisories. Unknown target kinds and malformed entries are skipped and
//! counted rather than guessed at.

use guard_command::supply_chain_bundle::{
    load_supply_chain_bundle_response, SupplyChainBundleError,
};
use guard_command::supply_chain_bundle_cache_trust::{
    validate_cached_supply_chain_bundle, CachedBundleRejection,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{parse_intervals, AdvisoryInput, PlatformInput, RangeInput, MAX_RANGES};

pub(crate) const FEATURE: &str = "runtime-identity-assess-bundle-v1";
const SECTION_KEY: &str = "runtimeAdvisories";
const SECTION_SCHEMA: &str = "runtime-advisories.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CachedBundleInput {
    response: Value,
    workspace_id: String,
    #[serde(default)]
    sync_keyring: Option<Value>,
    #[serde(default)]
    synced_bundle_version: Option<String>,
    #[serde(default)]
    now: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Section {
    schema_version: String,
    ruleset_version: String,
    entries: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    advisory_id: String,
    normalized_severity: String,
    known_exploited: bool,
    include_prerelease: bool,
    backport_build_ids: Vec<String>,
    ranges: Vec<Range>,
    target: Target,
    title: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Range {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Target {
    #[serde(rename_all = "camelCase")]
    Runtime {
        family: String,
        vendor: String,
        platforms: Vec<PlatformInput>,
        version_scheme: String,
    },
    #[serde(rename_all = "camelCase")]
    BundledComponent {
        component: String,
        host: Host,
        platforms: Vec<PlatformInput>,
        version_scheme: String,
    },
}

#[derive(Debug, Deserialize)]
struct Host {
    family: String,
    vendor: String,
}

/// The advisories the cached bundle supplies, and a report of where they came
/// from. Advisories are empty unless the source state is `verified`.
pub(crate) fn bundle_advisories(input: Option<&CachedBundleInput>) -> (Vec<AdvisoryInput>, Value) {
    let Some(input) = input else {
        return (Vec::new(), source("absent", None, None));
    };
    evaluate(input, input.now)
}

/// Launch admission keeps an expired bundle's rules for positive matches only:
/// PRD retains stale affected verdicts while stale absence stays unknown. The
/// bundle is re-checked as of its own expiry, so scope, payload hash,
/// signature, key state and rollback are still enforced; only freshness is
/// relaxed, and the report stays `stale` so callers never clear on it.
pub(crate) fn launch_bundle_advisories(input: Option<&CachedBundleInput>) -> LaunchAdvisories {
    let (advisories, source) = bundle_advisories(input);
    let current = LaunchAdvisories { advisories, source };
    let (Some(input), Some("bundle_expired")) = (input, current.source["reason"].as_str()) else {
        return current;
    };
    let Some(expired_at) = load_supply_chain_bundle_response(&input.response)
        .ok()
        .and_then(|typed| typed.bundle.expires_at_timestamp().ok())
    else {
        return current;
    };
    let (advisories, mut source) = evaluate(input, Some(expired_at));
    if source["state"] != "verified" {
        return current;
    }
    source["state"] = json!("stale");
    source["reason"] = json!("bundle_expired");
    source["expired_at"] = json!(expired_at);
    LaunchAdvisories { advisories, source }
}

/// Bundle rules verified once and reused across launch checks.
#[derive(Debug)]
pub(crate) struct LaunchAdvisories {
    pub(super) advisories: Vec<AdvisoryInput>,
    pub(crate) source: Value,
}

impl CachedBundleInput {
    pub(crate) fn new(
        response: Value,
        workspace_id: String,
        sync_keyring: Option<Value>,
        synced_bundle_version: Option<String>,
    ) -> Self {
        Self {
            response,
            workspace_id,
            sync_keyring,
            synced_bundle_version,
            now: None,
        }
    }
}

fn evaluate(input: &CachedBundleInput, now: Option<f64>) -> (Vec<AdvisoryInput>, Value) {
    let typed = match load_supply_chain_bundle_response(&input.response) {
        Ok(typed) => typed,
        Err(_) => {
            return (
                Vec::new(),
                source("invalid", Some("bundle_malformed"), None),
            )
        }
    };
    let anchored = match validate_cached_supply_chain_bundle(
        &typed,
        &input.workspace_id,
        now,
        input.sync_keyring.as_ref(),
        input.synced_bundle_version.as_deref(),
    ) {
        Ok(anchored) => anchored,
        Err(rejection) => {
            let (state, reason) = rejection_state(&rejection);
            return (Vec::new(), source(state, Some(reason), None));
        }
    };
    let bundle_version = typed.bundle.bundle_version.as_str();
    let verified = |reason: Option<&str>, extra: Value| {
        let mut report = source("verified", reason, Some(bundle_version));
        report["anchored"] = json!(anchored);
        if let (Some(report), Value::Object(extra)) = (report.as_object_mut(), extra) {
            report.extend(extra);
        }
        report
    };
    let Some(raw) = typed.signed_bundle.get(SECTION_KEY) else {
        return (Vec::new(), verified(Some("section_absent"), json!({})));
    };
    let Ok(section) = Section::deserialize(raw) else {
        return (
            Vec::new(),
            source(
                "unsupported",
                Some("section_malformed"),
                Some(bundle_version),
            ),
        );
    };
    if section.schema_version != SECTION_SCHEMA {
        return (
            Vec::new(),
            source(
                "unsupported",
                Some("schema_unsupported"),
                Some(bundle_version),
            ),
        );
    }
    let advisories: Vec<AdvisoryInput> = section
        .entries
        .iter()
        .filter_map(|raw| Entry::deserialize(raw).ok().map(advisory_input))
        .filter(usable)
        .collect();
    let skipped = section.entries.len() - advisories.len();
    let report = verified(
        None,
        json!({
            "ruleset_version": section.ruleset_version,
            "entries": advisories.len(),
            "entries_skipped": skipped,
        }),
    );
    (advisories, report)
}

fn advisory_input(entry: Entry) -> AdvisoryInput {
    let (family, vendor, platforms, version_scheme, bundled_component) = match entry.target {
        Target::Runtime {
            family,
            vendor,
            platforms,
            version_scheme,
        } => (family, vendor, platforms, version_scheme, None),
        Target::BundledComponent {
            component,
            host,
            platforms,
            version_scheme,
        } => (
            host.family,
            host.vendor,
            platforms,
            version_scheme,
            Some(component),
        ),
    };
    AdvisoryInput {
        advisory_id: entry.advisory_id,
        family,
        vendor: Some(vendor),
        version_scheme,
        ranges: entry
            .ranges
            .into_iter()
            .map(|range| RangeInput {
                introduced: range.introduced,
                fixed: range.fixed,
                last_affected: range.last_affected,
            })
            .collect(),
        include_prerelease: entry.include_prerelease,
        backport_build_ids: entry.backport_build_ids,
        platforms,
        bundled_component,
        severity: Some(entry.normalized_severity),
        known_exploited: entry.known_exploited,
        title: Some(entry.title),
    }
}

/// A signed entry this build cannot evaluate is skipped, never allowed to
/// fail the whole assessment.
fn usable(advisory: &AdvisoryInput) -> bool {
    advisory.ranges.len() <= MAX_RANGES
        && advisory.backport_build_ids.len() <= MAX_RANGES
        && advisory.platforms.len() <= MAX_RANGES
        && parse_intervals(advisory).is_ok()
}

fn rejection_state(rejection: &CachedBundleRejection) -> (&'static str, &'static str) {
    match rejection {
        CachedBundleRejection::Scope(_) => ("invalid", "scope_rejected"),
        CachedBundleRejection::Bundle(error) => match error {
            // An expired bundle was well formed but is too old to trust;
            // its signature is not checked once freshness fails.
            SupplyChainBundleError::Expired(_) => ("stale", "bundle_expired"),
            SupplyChainBundleError::Rollback(_) => ("invalid", "bundle_rollback"),
            SupplyChainBundleError::Signature(_) => ("invalid", "signature_invalid"),
            SupplyChainBundleError::PayloadHash(_) => ("invalid", "payload_hash_mismatch"),
            SupplyChainBundleError::Keyring(_) => ("invalid", "keyring_rejected"),
            SupplyChainBundleError::Malformed(_) => ("invalid", "bundle_malformed"),
        },
    }
}

fn source(state: &str, reason: Option<&str>, bundle_version: Option<&str>) -> Value {
    json!({
        "state": state,
        "reason": reason,
        "bundle_version": bundle_version,
        "anchored": false,
        "ruleset_version": null,
        "entries": 0,
        "entries_skipped": 0,
    })
}

#[cfg(test)]
#[path = "runtime_identity_bundle_tests.rs"]
mod tests;
