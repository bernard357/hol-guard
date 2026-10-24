//! Per-artifact advisory matching and the per-advisory remediation verdict.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::{
    AdvisoryInput, Artifact, Coverage, InstanceInput, InstanceState, LocationInput, LocationState,
    Match, Request,
};
use crate::runtime_identity_range::{Interval, SemVer};

/// `None` when the advisory is about a different runtime entirely.
pub(super) fn match_artifact(
    artifact: &Artifact<'_>,
    advisory: &AdvisoryInput,
    intervals: &[Interval],
) -> Option<Match> {
    let input = artifact.input;
    if !input.family.eq_ignore_ascii_case(&advisory.family) {
        return None;
    }
    if let Some(vendor) = &advisory.vendor {
        match &input.vendor {
            None => return Some(Match::Unknown("vendor_unknown")),
            Some(observed) if !observed.eq_ignore_ascii_case(vendor) => return None,
            Some(_) => {}
        }
    }
    if advisory.version_scheme != "semver" {
        return Some(Match::Unknown("version_scheme_unsupported"));
    }
    if intervals.is_empty() {
        return Some(Match::Unknown("no_ranges"));
    }
    let Some(raw) = &input.version else {
        return Some(Match::Unknown("version_unknown"));
    };
    let Some(version) = SemVer::parse(raw) else {
        return Some(Match::Unknown("version_unparseable"));
    };
    if version.is_prerelease() && !advisory.include_prerelease {
        return Some(Match::Unknown("prerelease_unhandled"));
    }
    let in_range = intervals.iter().any(|interval| interval.contains(&version));
    let backported = input
        .build_id
        .as_ref()
        .is_some_and(|build| advisory.backport_build_ids.contains(build));
    Some(match (in_range, backported, artifact.assurance.trusted()) {
        (true, true, true) => Match::NotAffected("vendor_backport"),
        (true, true, false) => Match::Unknown("backport_unverified"),
        (true, false, _) => Match::Affected("in_range"),
        (false, _, true) => Match::NotAffected("outside_ranges"),
        (false, _, false) => Match::Unknown("outside_ranges_untrusted"),
    })
}

pub(super) fn advisory_verdict(
    request: &Request,
    artifacts: &BTreeMap<&str, Artifact<'_>>,
    locations: &BTreeMap<&str, &LocationInput>,
    advisory_id: &str,
    by_artifact: &BTreeMap<&str, Match>,
) -> Value {
    let ids_where = |wanted: fn(&Match) -> bool| -> BTreeSet<&str> {
        by_artifact
            .iter()
            .filter(|(_, found)| wanted(found))
            .map(|(id, _)| *id)
            .collect()
    };
    let affected = ids_where(|found| matches!(found, Match::Affected(_)));
    let cleared = ids_where(|found| matches!(found, Match::NotAffected(_)));
    let unknown_match = by_artifact
        .values()
        .any(|found| matches!(found, Match::Unknown(_)));

    let live_affected: Vec<&InstanceInput> = request
        .instances
        .iter()
        .filter(|instance| {
            affected.contains(instance.artifact_id.as_str())
                && instance.state != InstanceState::Exited
        })
        .collect();
    let running_affected: Vec<&InstanceInput> = live_affected
        .iter()
        .copied()
        .filter(|instance| instance.state == InstanceState::Running)
        .collect();
    let replacements: Vec<&str> = request
        .instances
        .iter()
        .filter(|instance| {
            instance.state == InstanceState::Running
                && instance.coverage == Coverage::BoundLaunch
                && cleared.contains(instance.artifact_id.as_str())
                && artifacts
                    .get(instance.artifact_id.as_str())
                    .is_some_and(|artifact| artifact.assurance.trusted())
        })
        .map(|instance| instance.instance_id.as_str())
        .collect();
    let installed_affected = locations.values().any(|location| {
        location.state != LocationState::Missing
            && location
                .artifact_id
                .as_deref()
                .is_some_and(|id| affected.contains(id))
    });
    // The file at an affected process's location has already been replaced by
    // a cleared build: the process still runs the old one.
    let replaced_on_disk = |instance: &&InstanceInput| {
        instance
            .location_id
            .as_deref()
            .and_then(|id| locations.get(id))
            .is_some_and(|location| {
                location.state == LocationState::Present
                    && location
                        .artifact_id
                        .as_deref()
                        .is_some_and(|id| cleared.contains(id))
            })
    };

    let mut reasons: Vec<&str> = Vec::new();
    let verdict = if affected.is_empty() {
        if unknown_match {
            reasons.push("match_unknown");
            "unknown"
        } else if by_artifact.is_empty() {
            "not_observed"
        } else {
            "not_affected"
        }
    } else if !running_affected.is_empty() {
        if running_affected.iter().all(replaced_on_disk) {
            reasons.push("affected_instance_running_after_replacement");
            "restart_required"
        } else {
            reasons.push("affected_instance_running");
            "affected"
        }
    } else if !live_affected.is_empty() {
        reasons.push("affected_instance_state_unknown");
        "unknown"
    } else if installed_affected {
        reasons.push("affected_artifact_installed");
        "affected"
    } else {
        if !request.scope_complete {
            reasons.push("scope_incomplete");
        }
        if replacements.is_empty() {
            reasons.push("no_bound_trusted_replacement");
        }
        if unknown_match {
            reasons.push("match_unknown");
        }
        if reasons.is_empty() {
            "fixed_verified"
        } else {
            "fix_unverified"
        }
    };

    json!({
        "advisory_id": advisory_id,
        "verdict": verdict,
        "reasons": reasons,
        "affected_artifact_ids": affected,
        "affected_instance_ids": live_affected
            .iter()
            .map(|instance| instance.instance_id.as_str())
            .collect::<Vec<_>>(),
        "replacement_instance_ids": replacements,
    })
}
