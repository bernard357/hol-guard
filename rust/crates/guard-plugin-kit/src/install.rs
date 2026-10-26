//! `hol-guard plugin install|uninstall`: turn a listing's install spec into
//! the argument vectors each runtime's own CLI takes.
//!
//! The spec comes from the HOL registry and is untrusted. It carries only
//! identifiers (repository, marketplace and plugin names), never command
//! text. Every identifier is checked here and the argv is built from fixed
//! program names, so a listing cannot make Guard run anything else. The Kit
//! still runs nothing itself: the CLI shows the plan and runs it only on
//! `--apply`, one runtime at a time.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SPEC_SCHEMA: &str = "hol.plugin-install-spec.v1";

/// Runtimes the spec may name, in the order the plan lists them.
const RUNTIMES: [&str; 3] = ["claude-code", "codex", "agent-skills"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Uninstall,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    slug: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(rename = "listingUrl")]
    listing_url: String,
    #[serde(default, rename = "trustScore")]
    trust_score: Option<f64>,
    targets: Vec<Target>,
    #[serde(default)]
    manual: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    runtime: String,
    #[serde(default)]
    marketplace: Option<Marketplace>,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marketplace {
    repository: String,
    name: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Step {
    pub runtime: &'static str,
    /// The program each command starts with; the CLI checks it is on PATH.
    pub program: &'static str,
    /// True when the program was found on this machine.
    pub available: bool,
    /// False when Guard only prints the commands and never runs them.
    pub automatic: bool,
    pub commands: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub action: &'static str,
    pub slug: String,
    pub name: String,
    pub version: Option<String>,
    pub repository: Option<String>,
    pub listing_url: String,
    pub trust_score: Option<f64>,
    pub steps: Vec<Step>,
    /// Runtimes the listing supports that Guard cannot install for you.
    pub manual: Vec<String>,
}

/// GitHub `owner/name`: owner 1–39 of `[A-Za-z0-9-]` not starting with `-`,
/// name 1–100 of `[A-Za-z0-9._-]` not starting with `.` or `-`.
pub fn valid_repository(value: &str) -> bool {
    let Some((owner, name)) = value.split_once('/') else {
        return false;
    };
    let owner_ok = (1..=39).contains(&owner.len())
        && !owner.starts_with('-')
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let name_ok = (1..=100).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    owner_ok && name_ok
}

/// Marketplace and plugin entry names: 1–128 of `[A-Za-z0-9._-]`, starting
/// with a letter or digit, so none can be read as a flag.
pub fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(crate) fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

const INVALID: &str = "plugin_kit_install_spec_invalid";

/// Where listing pages live. HOL's own site unless the user pointed Guard at
/// another install-spec endpoint (a local portal in tests), in which case the
/// CLI passes that endpoint's origin and listings must live there instead.
pub const HOL_ORIGIN: &str = "https://hol.org/";

/// An origin the CLI may pass: `http(s)://host[:port]/`, nothing after it.
pub(crate) fn valid_origin(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let Some(authority) = rest.strip_suffix('/') else {
        return false;
    };
    (1..=255).contains(&authority.len())
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Hosts an install-spec override may reach over plain http: this machine,
/// or the host a container runs on.
const LOCAL_HOSTS: [&str; 4] = ["localhost", "127.0.0.1", "[::1]", "host.docker.internal"];

/// Checks an `HOL_GUARD_PLUGIN_SPEC_URL` override and returns the origin its
/// listings must use: `scheme://host[:port]/`, lowercase, with a default port
/// left out so `:443` and no port compare equal. The CLI appends `?slug=` to
/// the value, so it may carry no query, fragment or credentials, and only
/// https leaves the machine.
pub(crate) fn endpoint_origin(value: &str) -> Option<String> {
    let printable = value
        .bytes()
        .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'?' | b'#' | b'@' | b'\\'));
    if value.len() > 2048 || !printable {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return None,
    };
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _)| authority);
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (literal, after) = inner.split_once(']')?;
        if literal.is_empty() || !literal.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return None;
        }
        (format!("[{}]", literal.to_ascii_lowercase()), after)
    } else {
        let end = authority.find(':').unwrap_or(authority.len());
        let host = &authority[..end];
        let labels_ok = host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if !labels_ok {
            return None;
        }
        (host.to_ascii_lowercase(), &authority[end..])
    };
    let port = match port {
        "" => default_port,
        port => {
            let digits = port.strip_prefix(':')?;
            if !(1..=5).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let number: u32 = digits.parse().ok()?;
            if !(1..=65535).contains(&number) {
                return None;
            }
            number
        }
    };
    if scheme == "http" && !LOCAL_HOSTS.contains(&host.as_str()) {
        return None;
    }
    Some(if port == default_port {
        format!("{scheme}://{host}/")
    } else {
        format!("{scheme}://{host}:{port}/")
    })
}

fn parse(spec: Value, origin: &str) -> Result<Spec, String> {
    let spec: Spec = serde_json::from_value(spec).map_err(|_| INVALID.to_owned())?;
    if spec.schema != SPEC_SCHEMA {
        return Err("plugin_kit_install_spec_unsupported".to_owned());
    }
    let listing_ok = spec
        .listing_url
        .strip_prefix(origin)
        .is_some_and(|rest| valid_text(rest, 300) && !rest.contains(char::is_whitespace));
    let version_ok = spec.version.as_deref().is_none_or(|v| valid_text(v, 64));
    let repository_ok = spec.repository.as_deref().is_none_or(valid_repository);
    let manual_ok = spec.manual.iter().all(|m| valid_identifier(m));
    if !valid_slug(&spec.slug)
        || !valid_text(&spec.name, 128)
        || !listing_ok
        || !version_ok
        || !repository_ok
        || !manual_ok
        || spec.targets.len() > RUNTIMES.len()
    {
        return Err(INVALID.to_owned());
    }
    let mut seen = BTreeSet::new();
    for target in &spec.targets {
        if !seen.insert(target.runtime.as_str()) {
            return Err(INVALID.to_owned());
        }
        let ok = match target.runtime.as_str() {
            "claude-code" | "codex" => {
                target.repository.is_none()
                    && target.plugin.as_deref().is_some_and(valid_identifier)
                    && target.marketplace.as_ref().is_some_and(|m| {
                        valid_repository(&m.repository) && valid_identifier(&m.name)
                    })
            }
            "agent-skills" => {
                target.marketplace.is_none()
                    && target.plugin.is_none()
                    && target.repository.as_deref().is_some_and(valid_repository)
            }
            _ => false,
        };
        if !ok {
            return Err(INVALID.to_owned());
        }
    }
    Ok(spec)
}

/// Check a spec with the same rules as a plan, without building one.
pub(crate) fn validate(spec: &Value, origin: &str) -> Result<(), String> {
    parse(spec.clone(), origin).map(|_| ())
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn step(target: &Target, action: Action, available: &BTreeSet<String>) -> Step {
    let marketplace_install = |program: &'static str, add: &str, remove: &str, list: &[&str]| {
        let market = target.marketplace.as_ref().expect("validated");
        let plugin = target.plugin.as_deref().expect("validated");
        let id = format!("{plugin}@{}", market.name);
        let commands = match action {
            Action::Install => vec![
                argv(&[program, "plugin", "marketplace", "add", &market.repository]),
                argv(&[program, "plugin", add, &id]),
            ],
            Action::Uninstall => vec![argv(&[program, "plugin", remove, &id])],
        };
        Step {
            runtime: "",
            program,
            available: available.contains(program),
            automatic: true,
            commands,
            verify: Some(argv(list)),
            note: (action == Action::Uninstall)
                .then_some("The marketplace stays registered, since other plugins may use it."),
        }
    };
    match target.runtime.as_str() {
        "claude-code" => Step {
            runtime: "claude-code",
            ..marketplace_install(
                "claude",
                "install",
                "uninstall",
                &["claude", "plugin", "list"],
            )
        },
        "codex" => Step {
            runtime: "codex",
            ..marketplace_install("codex", "add", "remove", &["codex", "plugin", "list"])
        },
        _ => {
            let repository = target.repository.as_deref().expect("validated");
            let commands = match action {
                Action::Install => vec![argv(&["npx", "skills", "add", repository])],
                Action::Uninstall => vec![argv(&["npx", "skills", "list"])],
            };
            Step {
                runtime: "agent-skills",
                program: "npx",
                available: available.contains("npx"),
                automatic: false,
                commands,
                verify: Some(argv(&["npx", "skills", "list"])),
                note: Some(match action {
                    Action::Install => "Run this yourself: the Skills CLI downloads a package from npm and installs for every agent it detects.",
                    Action::Uninstall => "Remove the skills with the Skills CLI; it lists what it installed.",
                }),
            }
        }
    }
}

/// Build the plan. `available` names the programs found on PATH and
/// `requested` limits it to some runtimes (empty means every target), and
/// `origin` is where listing pages must live (see [`HOL_ORIGIN`]).
pub fn plan(
    spec: Value,
    action: Action,
    available: &[String],
    requested: &[String],
    origin: &str,
) -> Result<Plan, String> {
    let spec = parse(spec, origin)?;
    if requested.iter().any(|r| !RUNTIMES.contains(&r.as_str())) {
        return Err("plugin_kit_install_runtime_unknown".to_owned());
    }
    let offered: BTreeSet<&str> = spec.targets.iter().map(|t| t.runtime.as_str()).collect();
    if requested.iter().any(|r| !offered.contains(r.as_str())) {
        return Err("plugin_kit_install_runtime_not_offered".to_owned());
    }
    let available: BTreeSet<String> = available.iter().cloned().collect();
    let mut steps: Vec<Step> = spec
        .targets
        .iter()
        .filter(|t| requested.is_empty() || requested.contains(&t.runtime))
        .map(|t| step(t, action, &available))
        .collect();
    steps.sort_by_key(|s| RUNTIMES.iter().position(|r| *r == s.runtime));
    Ok(Plan {
        action: match action {
            Action::Install => "install",
            Action::Uninstall => "uninstall",
        },
        slug: spec.slug,
        name: spec.name,
        version: spec.version,
        repository: spec.repository,
        listing_url: spec.listing_url,
        trust_score: spec.trust_score.filter(|s| s.is_finite()),
        steps,
        manual: spec.manual,
    })
}
