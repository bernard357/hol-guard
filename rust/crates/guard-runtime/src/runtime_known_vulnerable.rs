//! Known-vulnerable runtime admission. Before a shell command that launches
//! Node.js runs, the executable it names is identified and matched against
//! the runtime advisories in the cached, signed supply-chain bundle. A known
//! affected high or critical build raises the result to the action the policy
//! sets for `runtime_known_vulnerable`; everything else leaves it untouched.
//!
//! The check is preflight only: Guard identifies the file at the resolved
//! path before the harness runs the command, and does not bind that file to
//! the process the shell starts. Unknown identities, unconfirmed matches and
//! a missing or invalid bundle stay quiet. A bundle past its expiry still
//! reports matches it verified (with the expiry in the reason) but never
//! clears anything. Observe mode records the would-be decision as a warning.
//! Like the network overlay, this only ever raises the result's floor.

use std::path::{Path, PathBuf};

use guard_contracts::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolResultV1};
use serde_json::Value;

use crate::policy_enforcement::{risk_action, ActionFloor, AdmittedPolicySnapshot};
use crate::runtime_identity::LaunchAdvisories;
use crate::runtime_known_vulnerable_source as source;

pub(crate) const RISK_KEY: &str = "runtime_known_vulnerable";
const FINDING: &str = "native_runtime_known_vulnerable";
const OBSERVED: &str = "native_runtime_known_vulnerable_observed";
const RUNTIME_NAMES: &[&str] = &["node", "nodejs"];
/// Launches checked per command; a command naming more is checked up to here.
const MAX_LAUNCHES: usize = 8;

/// Whether `reason_code` is this overlay's review finding. It matched the
/// verified bundle, so it holds the hook verdict at review before execution.
pub(crate) fn is_review_finding(reason_code: &str) -> bool {
    reason_code == FINDING
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    advisory_id: String,
    severity: String,
    known_exploited: bool,
    version: String,
    resolved_path: String,
    expired_at: Option<f64>,
}

impl Finding {
    fn describe(&self) -> String {
        let mut text = format!(
            "Node.js {} at {} is affected by {} ({}{})",
            self.version,
            self.resolved_path,
            self.advisory_id,
            self.severity,
            if self.known_exploited {
                ", known exploited"
            } else {
                ""
            },
        );
        if self.expired_at.is_some() {
            text.push_str(", from a cached advisory bundle past its expiry");
        }
        text.push_str(". Checked before launch; not bound to the started process.");
        text
    }
}

/// [`apply`] for a hook envelope.
pub(crate) fn apply_to_envelope(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&AdmittedPolicySnapshot>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    let Some(snapshot) = policy_snapshot else {
        return result;
    };
    if result.minimum_action == "block"
        || result.action.event != "PreToolUse"
        || result.action.action_type != PreToolActionTypeV1::Command
    {
        return result;
    }
    let action = match risk_action(snapshot, &result.action.harness, RISK_KEY) {
        Ok(Some(action)) if action != "allow" => action,
        _ => return result,
    };
    let Some(command) = command_text(&envelope.raw_payload) else {
        return result;
    };
    let launches = runtime_launches(&command, envelope);
    if launches.is_empty() {
        return result;
    }
    let Some(advisories) = source::advisories(Path::new(&envelope.source.guard_home)) else {
        return result;
    };
    let finding = launches
        .iter()
        .find_map(|path| affected(path, &advisories));
    match finding {
        Some(finding) => raise(result, &finding, &action, snapshot.mode == "observe"),
        None => result,
    }
}

/// The shell text of a command tool call, a `[shell, -c, script]` argv
/// included.
fn command_text(payload: &Value) -> Option<String> {
    match payload.pointer("/tool_input/command")? {
        Value::String(text) => Some(text.clone()),
        Value::Array(argv) => {
            let argv: Vec<&str> = argv.iter().map(Value::as_str).collect::<Option<_>>()?;
            match argv.as_slice() {
                [_, flag, script] if matches!(*flag, "-c" | "-lc") => Some((*script).to_owned()),
                parts => Some(parts.join(" ")),
            }
        }
        _ => None,
    }
    .filter(|text| !text.trim().is_empty() && text.len() <= 65_536)
}

/// The executables a command launches as Node.js, resolved the way the shell
/// would: a bare name through the hook's `PATH`, a relative one from `cwd`.
/// A segment that overrides `PATH` is skipped; Guard cannot say which file it
/// would run.
fn runtime_launches(command: &str, envelope: &GuardHookEnvelopeV2) -> Vec<PathBuf> {
    let cwd = envelope.source.cwd.as_deref().map(Path::new);
    let home = Path::new(&envelope.source.home_dir);
    let search_path = envelope
        .source
        .execution_environment
        .as_ref()
        .map(|environment| environment.path.as_str());
    let mut texts = vec![command.to_owned()];
    let mut launches = Vec::new();
    let mut parsed = 0;
    while let Some(text) = texts.pop() {
        parsed += 1;
        if parsed > MAX_LAUNCHES * 2 || text.trim().is_empty() {
            break;
        }
        let model = guard_command::command_model::parse_shell_command(
            &text,
            cwd,
            Some(home),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        );
        texts.extend(model.embedded_commands.iter().map(|embedded| embedded.text.clone()));
        for segment in &model.segments {
            if segment.path_overridden {
                continue;
            }
            let Some(executable) = segment.executable.as_deref() else {
                continue;
            };
            if !is_runtime_name(executable) {
                continue;
            }
            if let Some(path) = resolve(executable, cwd, search_path) {
                if !launches.contains(&path) {
                    launches.push(path);
                }
            }
            if launches.len() >= MAX_LAUNCHES {
                return launches;
            }
        }
    }
    launches
}

fn is_runtime_name(executable: &str) -> bool {
    let name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    RUNTIME_NAMES.contains(&name)
}

fn resolve(executable: &str, cwd: Option<&Path>, search_path: Option<&str>) -> Option<PathBuf> {
    let path = Path::new(executable);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    if path.components().count() > 1 {
        return cwd.map(|cwd| cwd.join(path));
    }
    let environment = std::collections::BTreeMap::new();
    crate::runtime_identity_launch::which(
        executable,
        search_path,
        &crate::runtime_identity_launch::Environment(&environment),
    )
    .map(PathBuf::from)
}

/// The strongest high or critical advisory this executable's build is known
/// to be affected by.
fn affected(path: &Path, advisories: &LaunchAdvisories) -> Option<Finding> {
    let (resolved_path, artifact) = source::probe(path)?;
    let report = crate::runtime_identity::assess_launch(&artifact, advisories).ok()?;
    let affected_ids: Vec<&str> = report["artifacts"]
        .as_array()?
        .iter()
        .flat_map(|row| row["matches"].as_array().into_iter().flatten())
        .filter(|row| row["status"] == "affected")
        .filter_map(|row| row["advisory_id"].as_str())
        .collect();
    let best = report["advisories"]
        .as_array()?
        .iter()
        .filter(|row| {
            row["advisory_id"]
                .as_str()
                .is_some_and(|id| affected_ids.contains(&id))
        })
        .filter_map(|row| {
            let rank = match row["severity"].as_str()? {
                "critical" => 2,
                "high" => 1,
                _ => return None,
            };
            Some((rank, row["known_exploited"] == true, row))
        })
        .max_by_key(|(rank, exploited, _)| (*rank, *exploited))?;
    let (_, known_exploited, row) = best;
    Some(Finding {
        advisory_id: row["advisory_id"].as_str()?.to_owned(),
        severity: row["severity"].as_str()?.to_owned(),
        known_exploited,
        version: artifact["version"].as_str().unwrap_or("unknown").to_owned(),
        resolved_path,
        expired_at: (advisories.source["state"] == "stale")
            .then(|| advisories.source["expired_at"].as_f64())
            .flatten(),
    })
}

/// Raises `result` to the configured action for a finding. Observe mode, and
/// a `warn` setting, record it as a warning over an otherwise allowed call.
pub(crate) fn raise(
    mut result: PreToolResultV1,
    finding: &Finding,
    action: &str,
    observe: bool,
) -> PreToolResultV1 {
    let (Some(minimum), Some(policy), Some(configured)) = (
        ActionFloor::parse(&result.minimum_action),
        ActionFloor::parse(&result.policy_action),
        ActionFloor::parse(action),
    ) else {
        return result;
    };
    let (floor, floor_action, reason_code) = if observe || configured <= ActionFloor::Warn {
        (ActionFloor::Warn, "warn", OBSERVED)
    } else {
        (configured, action, FINDING)
    };
    if minimum > floor {
        return result;
    }
    let reason = if reason_code == OBSERVED && configured > ActionFloor::Warn {
        format!("{} Guard would have required {action}.", finding.describe())
    } else {
        finding.describe()
    };
    if minimum == floor {
        // The same floor raised for another reason keeps its decision; a
        // review held by this finding carries its reason.
        if floor >= ActionFloor::Review {
            result.explicitly_benign = false;
            result.reason_code = reason_code.into();
            result.reason = reason;
        }
        return result;
    }
    result.minimum_action = floor_action.into();
    if policy < floor || floor == ActionFloor::Block {
        result.policy_action = floor_action.into();
    }
    result.decision = if floor <= ActionFloor::Warn {
        "allow"
    } else {
        "deny"
    }
    .into();
    result.explicitly_benign = false;
    result.reason_code = reason_code.into();
    result.reason = reason;
    result
}

#[cfg(test)]
#[path = "runtime_known_vulnerable_tests.rs"]
mod tests;
