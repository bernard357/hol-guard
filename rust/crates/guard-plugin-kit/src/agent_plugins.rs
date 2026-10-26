//! `hol-guard plugin check --spec agent-plugins-1.0`: whether a plugin root
//! conforms to the Agent Plugins Specification 1.0.0, and what a conforming
//! client would do with each part that does not.
//!
//! The rules follow the specification text and its two schemas
//! (`schemas/1.0.0/plugin.schema.json` and `mcp.schema.json` at tag `v1.0.0`
//! of github.com/agentplugins/agent-plugins-spec). They are written out here
//! because the specification forbids fetching a schema while loading a
//! plugin, and the Kit makes no network calls. Where the text and the schemas
//! differ, the text wins, as the specification says.
//!
//! Every finding names the section it comes from and its effect on a client:
//! reject the plugin, ignore a field, skip a skill or server, disable MCP, or
//! treat a component type as invalid. A package passes only when a client
//! would load all of it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::detect::skill::frontmatter;
use crate::walk::MAX_TEXT_BYTES;

pub const SPEC: &str = "agent-plugins-1.0";
pub const VERSION: &str = "1.0.0";
pub const PLUGIN_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json";
pub const MCP_SCHEMA: &str = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json";
const SCHEMA_PREFIX: &str = "https://agent-plugins.org/schemas/";

const MANIFEST_FIELDS: [&str; 10] = [
    "$schema",
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "extensions",
];
const MAX_NAME: usize = 64;
const MAX_SKILL_DESCRIPTION: usize = 1024;
const MAX_SKILLS: usize = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The client rejects the plugin and loads none of it.
    RejectPlugin,
    /// The client reports the field and ignores it.
    IgnoreField,
    /// The client treats the whole component type as invalid.
    InvalidComponent,
    /// The client disables MCP for the plugin.
    DisableMcp,
    SkipSkill,
    SkipServer,
    /// Advice only; the client loads the part.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub path: String,
    pub message: String,
    /// The section of the specification the finding comes from.
    pub section: &'static str,
    pub effect: Effect,
}

#[derive(Default)]
struct Report {
    findings: Vec<Finding>,
}

impl Report {
    fn error(
        &mut self,
        code: &'static str,
        path: &str,
        section: &'static str,
        effect: Effect,
        message: impl Into<String>,
    ) {
        self.findings.push(Finding {
            level: Level::Error,
            code,
            path: path.to_owned(),
            message: message.into(),
            section,
            effect,
        });
    }

    fn warning(
        &mut self,
        code: &'static str,
        path: &str,
        section: &'static str,
        message: impl Into<String>,
    ) {
        self.findings.push(Finding {
            level: Level::Warning,
            code,
            path: path.to_owned(),
            message: message.into(),
            section,
            effect: Effect::None,
        });
    }
}

/// Checks `root` (already resolved) and returns the conformance report.
pub fn check(root: &Path, strict: bool) -> Value {
    let mut report = Report::default();
    let manifest = manifest(root, &mut report);
    let mut skills = Vec::new();
    let mut servers = Vec::new();
    if manifest.is_some() {
        skills = discover_skills(root, &mut report);
        servers = mcp_servers(root, &mut report);
    }
    let errors = report
        .findings
        .iter()
        .filter(|finding| finding.level == Level::Error)
        .count();
    let warnings = report.findings.len() - errors;
    let field = |key: &str| {
        manifest
            .as_ref()
            .and_then(|manifest| manifest.get(key))
            .and_then(Value::as_str)
    };
    json!({
        "spec": SPEC,
        "version": VERSION,
        "passed": errors == 0 && (!strict || warnings == 0),
        "plugin": {"name": field("name"), "version": field("version")},
        "components": {"skills": skills, "mcp_servers": servers},
        "diagnostics": report.findings,
        "summary": {"errors": errors, "warnings": warnings},
    })
}

/// The manifest when a client would load the plugin, else `None`.
fn manifest(root: &Path, report: &mut Report) -> Option<Map<String, Value>> {
    const PATH: &str = "plugin.json";
    let reject = |report: &mut Report, code, section, message: &str| {
        report.error(code, PATH, section, Effect::RejectPlugin, message);
    };
    let text = match read_inside(root, Path::new(PATH)) {
        Read::Missing => {
            reject(
                report,
                "manifest_missing",
                "4.1",
                "A plugin needs plugin.json at its root.",
            );
            return None;
        }
        Read::Outside => {
            reject(
                report,
                "manifest_outside_root",
                "4.1",
                "plugin.json resolves outside the plugin folder.",
            );
            return None;
        }
        Read::NotFile | Read::Unreadable => {
            reject(
                report,
                "manifest_unreadable",
                "5.2",
                "plugin.json must be a readable UTF-8 file of at most 1 MiB.",
            );
            return None;
        }
        Read::Text(text) => text,
    };
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(&text) else {
        reject(
            report,
            "manifest_invalid_json",
            "5.2",
            "plugin.json must hold one JSON object.",
        );
        return None;
    };
    let mut fatal = false;
    for key in document.keys() {
        if !MANIFEST_FIELDS.contains(&key.as_str()) {
            report.error(
                "manifest_unknown_field",
                PATH,
                "5.2",
                Effect::IgnoreField,
                format!("`{key}` is not an Agent Plugins field; clients ignore it. Client data belongs under `extensions`."),
            );
        }
    }
    match document.get("$schema") {
        Some(Value::String(schema)) if schema == PLUGIN_SCHEMA => {}
        Some(Value::String(schema)) => {
            fatal = true;
            match declared_version(schema, "plugin.schema.json") {
                Some(version) => reject(
                    report,
                    "spec_version_unsupported",
                    "5.2",
                    &format!(
                        "plugin.json targets Agent Plugins {version}; this check covers {VERSION}."
                    ),
                ),
                None => reject(
                    report,
                    "schema_unrecognized",
                    "5.2",
                    &format!("`$schema` must be {PLUGIN_SCHEMA}."),
                ),
            }
        }
        _ => {
            fatal = true;
            reject(
                report,
                "schema_missing",
                "5.3",
                &format!("plugin.json needs `\"$schema\": \"{PLUGIN_SCHEMA}\"`."),
            );
        }
    }
    match document.get("name") {
        Some(Value::String(name)) if valid_plugin_name(name) => {}
        Some(Value::String(_)) => {
            fatal = true;
            reject(
                report,
                "name_invalid",
                "5.5",
                "`name` must be 1-64 lowercase letters, digits, hyphens or periods, start and end with a letter or digit, and have no `--` or `..`.",
            );
        }
        _ => {
            fatal = true;
            reject(
                report,
                "name_missing",
                "5.3",
                "plugin.json needs a `name` string.",
            );
        }
    }
    for key in [
        "version",
        "description",
        "homepage",
        "repository",
        "license",
    ] {
        if document.get(key).is_some_and(|value| !value.is_string()) {
            fatal = true;
            reject(
                report,
                "field_type_invalid",
                "5.4",
                &format!("`{key}` must be a string."),
            );
        }
    }
    if let Some(author) = document.get("author") {
        let valid = author.as_object().is_some_and(|author| {
            author.iter().all(|(key, value)| {
                matches!(key.as_str(), "name" | "email" | "url") && value.is_string()
            })
        });
        if !valid {
            fatal = true;
            reject(
                report,
                "author_invalid",
                "5.4",
                "`author` may hold only `name`, `email` and `url` strings.",
            );
        }
    }
    if let Some(keywords) = document.get("keywords") {
        if !keywords
            .as_array()
            .is_some_and(|keywords| keywords.iter().all(Value::is_string))
        {
            fatal = true;
            reject(
                report,
                "keywords_invalid",
                "5.4",
                "`keywords` must be a list of strings.",
            );
        }
    }
    match document.get("extensions") {
        None => {}
        Some(Value::Object(extensions)) => {
            for (namespace, value) in extensions {
                if !value.is_object() {
                    fatal = true;
                    reject(
                        report,
                        "extension_not_object",
                        "8.1",
                        &format!("`extensions.{namespace}` must be an object."),
                    );
                }
            }
        }
        Some(_) => report.error(
            "extensions_not_object",
            PATH,
            "8.1",
            Effect::IgnoreField,
            "`extensions` must be an object keyed by reverse-domain namespace; clients ignore it.",
        ),
    }
    if let Some(Value::String(version)) = document.get("version") {
        if !crate::check::is_semver(version) {
            report.warning(
                "version_not_semver",
                PATH,
                "10.2",
                "Use a semantic version such as 1.2.0.",
            );
        }
    }
    (!fatal).then_some(document)
}

/// The skills a client would load from `skills/`, by name.
fn discover_skills(root: &Path, report: &mut Report) -> Vec<String> {
    const PATH: &str = "skills";
    let dir = root.join(PATH);
    if fs::symlink_metadata(&dir).is_err() {
        return Vec::new();
    }
    let Some(resolved) = resolve_inside(root, &dir) else {
        report.error(
            "skills_outside_root",
            PATH,
            "4.1",
            Effect::InvalidComponent,
            "skills/ resolves outside the plugin folder; clients load no skills.",
        );
        return Vec::new();
    };
    if !resolved.is_dir() {
        report.error(
            "skills_not_directory",
            PATH,
            "6.2",
            Effect::InvalidComponent,
            "skills must be a folder; clients load no skills.",
        );
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&resolved) else {
        report.error(
            "skills_unreadable",
            PATH,
            "6.2",
            Effect::InvalidComponent,
            "skills/ could not be read.",
        );
        return Vec::new();
    };
    let mut children: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .take(MAX_SKILLS)
        .collect();
    children.sort();
    let mut names = Vec::new();
    for child in children {
        let relative = format!("{PATH}/{child}/SKILL.md");
        let skill = dir.join(&child).join("SKILL.md");
        if fs::symlink_metadata(&skill).is_err() {
            continue;
        }
        let text = match read_inside(root, Path::new(&relative)) {
            Read::Outside => {
                report.error(
                    "skill_outside_root",
                    &relative,
                    "4.1",
                    Effect::SkipSkill,
                    "SKILL.md resolves outside the plugin folder.",
                );
                continue;
            }
            // Only a SKILL.md that is a regular file makes a skill.
            Read::Missing | Read::NotFile => continue,
            Read::Unreadable => {
                report.error(
                    "skill_unreadable",
                    &relative,
                    "7.1",
                    Effect::SkipSkill,
                    "SKILL.md must be readable UTF-8 of at most 1 MiB.",
                );
                continue;
            }
            Read::Text(text) => text,
        };
        let fields = frontmatter(&text);
        let name = fields.get("name").map(String::as_str).unwrap_or("");
        let description = fields.get("description").map(String::as_str).unwrap_or("");
        if !valid_skill_name(name) {
            report.error(
                "skill_name_invalid",
                &relative,
                "7.1",
                Effect::SkipSkill,
                "Agent Skills need a frontmatter `name` of 1-64 lowercase letters, digits and single hyphens.",
            );
        } else if name != child {
            report.error(
                "skill_name_mismatch",
                &relative,
                "7.1",
                Effect::SkipSkill,
                format!("The skill is named `{name}` but its folder is `{child}`; Agent Skills require them to match."),
            );
        } else if description.is_empty() || description.chars().count() > MAX_SKILL_DESCRIPTION {
            report.error(
                "skill_description_invalid",
                &relative,
                "7.1",
                Effect::SkipSkill,
                "Agent Skills need a frontmatter `description` of 1-1024 characters.",
            );
        } else {
            names.push(name.to_owned());
        }
    }
    names
}

/// The MCP servers a client would load from `mcp.json`, by name.
fn mcp_servers(root: &Path, report: &mut Report) -> Vec<String> {
    const PATH: &str = "mcp.json";
    let disable = |report: &mut Report, code, section, message: &str| {
        report.error(code, PATH, section, Effect::DisableMcp, message);
    };
    let text = match read_inside(root, Path::new(PATH)) {
        Read::Missing => return Vec::new(),
        Read::Outside => {
            report.error(
                "mcp_outside_root",
                PATH,
                "4.1",
                Effect::InvalidComponent,
                "mcp.json resolves outside the plugin folder; clients load no MCP servers.",
            );
            return Vec::new();
        }
        Read::NotFile => {
            report.error(
                "mcp_not_file",
                PATH,
                "6.2",
                Effect::InvalidComponent,
                "mcp.json must be a file; clients load no MCP servers.",
            );
            return Vec::new();
        }
        Read::Unreadable => {
            disable(
                report,
                "mcp_unreadable",
                "7.2.2",
                "mcp.json must be readable UTF-8 of at most 1 MiB.",
            );
            return Vec::new();
        }
        Read::Text(text) => text,
    };
    let Ok(Value::Object(document)) = serde_json::from_str::<Value>(&text) else {
        disable(
            report,
            "mcp_invalid_json",
            "7.2.2",
            "mcp.json must hold one JSON object.",
        );
        return Vec::new();
    };
    let mut disabled = false;
    for key in document.keys() {
        if key != "$schema" && key != "mcpServers" {
            disabled = true;
            disable(
                report,
                "mcp_unknown_field",
                "7.2.1",
                &format!("mcp.json allows only `$schema` and `mcpServers`, not `{key}`."),
            );
        }
    }
    match document.get("$schema") {
        Some(Value::String(schema)) if schema == MCP_SCHEMA => {}
        Some(Value::String(schema)) if declared_version(schema, "mcp.schema.json").is_some() => {
            disabled = true;
            disable(
                report,
                "mcp_version_mismatch",
                "10.1",
                &format!("mcp.json must target the same Agent Plugins version as plugin.json: {MCP_SCHEMA}."),
            );
        }
        _ => {
            disabled = true;
            disable(
                report,
                "mcp_schema_invalid",
                "7.2.1",
                &format!("mcp.json needs `\"$schema\": \"{MCP_SCHEMA}\"`."),
            );
        }
    }
    let Some(Value::Object(entries)) = document.get("mcpServers") else {
        disable(
            report,
            "mcp_servers_invalid",
            "7.2.1",
            "mcp.json needs an `mcpServers` object.",
        );
        return Vec::new();
    };
    if disabled {
        return Vec::new();
    }
    let mut loaded = Vec::new();
    for (name, entry) in entries {
        let path = format!("{PATH}#/mcpServers/{name}");
        if server_valid(root, &path, entry, report) {
            loaded.push(name.clone());
        }
    }
    loaded
}

fn server_valid(root: &Path, path: &str, entry: &Value, report: &mut Report) -> bool {
    let skip = |report: &mut Report, code, section, message: String| {
        report.error(code, path, section, Effect::SkipServer, message);
        false
    };
    let Some(entry) = entry.as_object() else {
        return skip(
            report,
            "mcp_server_invalid",
            "7.2.1",
            "A server entry must be an object.".into(),
        );
    };
    let kind = entry.get("type").and_then(Value::as_str).unwrap_or("");
    let allowed: &[&str] = match kind {
        "stdio" => &["type", "command", "args", "env", "cwd"],
        "streamable-http" | "sse" => &["type", "url", "headers"],
        _ => {
            return skip(
                report,
                "mcp_server_type_invalid",
                "7.2.1",
                "`type` must be `stdio`, `streamable-http` or `sse`.".into(),
            )
        }
    };
    if let Some(key) = entry.keys().find(|key| !allowed.contains(&key.as_str())) {
        return skip(
            report,
            "mcp_server_field_invalid",
            "7.2.1",
            format!("`{key}` is not a field of a `{kind}` server."),
        );
    }
    if kind == "stdio" {
        stdio_valid(root, entry, report, path)
    } else {
        if kind == "sse" {
            report.warning(
                "mcp_sse_deprecated",
                path,
                "7.2.1",
                "`sse` is the deprecated HTTP+SSE transport and optional for clients; prefer `streamable-http`.",
            );
        }
        remote_valid(entry, report, path)
    }
}

fn stdio_valid(root: &Path, entry: &Map<String, Value>, report: &mut Report, path: &str) -> bool {
    let skip = |report: &mut Report, code, message: &str| {
        report.error(code, path, "7.2.1", Effect::SkipServer, message);
        false
    };
    let command = match entry.get("command") {
        Some(Value::String(command)) if !command.is_empty() => command,
        _ => {
            return skip(
                report,
                "mcp_command_missing",
                "A stdio server needs a `command` string.",
            )
        }
    };
    if command.chars().any(char::is_whitespace) {
        return skip(
            report,
            "mcp_command_not_single_token",
            "`command` must be one executable, not a shell command line; put arguments in `args`.",
        );
    }
    if let Some(relative) = command.strip_prefix("./") {
        if !package_path_inside(root, relative) {
            return skip(
                report,
                "mcp_command_outside_root",
                "`command` resolves outside the plugin folder.",
            );
        }
    } else if command.contains(['/', '\\']) {
        return skip(
            report,
            "mcp_command_path_invalid",
            "`command` must be a bare executable name or a path starting with `./`.",
        );
    }
    if let Some(args) = entry.get("args") {
        if !args
            .as_array()
            .is_some_and(|args| args.iter().all(Value::is_string))
        {
            return skip(
                report,
                "mcp_args_invalid",
                "`args` must be a list of strings.",
            );
        }
    }
    if let Some(env) = entry.get("env") {
        let Some(env) = env.as_object() else {
            return skip(
                report,
                "mcp_env_invalid",
                "`env` must be an object of strings.",
            );
        };
        if env.values().any(|value| !value.is_string()) {
            return skip(
                report,
                "mcp_env_invalid",
                "`env` must be an object of strings.",
            );
        }
        if env
            .keys()
            .any(|key| key == "PLUGIN_ROOT" || key == "PLUGIN_DATA")
        {
            report.error(
                "mcp_env_reserved",
                path,
                "9.2",
                Effect::SkipServer,
                "`env` must not set PLUGIN_ROOT or PLUGIN_DATA; the client sets them.",
            );
            return false;
        }
        for (key, value) in env {
            if secret_name(key) && !value.as_str().unwrap_or("").contains("${PLUGIN_") {
                report.warning(
                    "mcp_env_may_hold_secret",
                    path,
                    "9.2",
                    format!("`env.{key}` looks like a credential. Values in env are package data that anyone can read; leave credentials to the client."),
                );
            }
        }
    }
    if let Some(cwd) = entry.get("cwd") {
        let Some(cwd) = cwd.as_str() else {
            return skip(report, "mcp_cwd_invalid", "`cwd` must be a string.");
        };
        let inside = if let Some(relative) = cwd.strip_prefix("./") {
            package_path_inside(root, relative)
        } else if let Some(rest) = placeholder_rest(cwd, "${PLUGIN_ROOT}") {
            package_path_inside(root, rest)
        } else if let Some(rest) = placeholder_rest(cwd, "${PLUGIN_DATA}") {
            lexically_inside(rest)
        } else {
            return skip(
                report,
                "mcp_cwd_invalid",
                "`cwd` must start with `./`, `${PLUGIN_ROOT}` or `${PLUGIN_DATA}`.",
            );
        };
        if !inside {
            return skip(
                report,
                "mcp_cwd_outside_root",
                "`cwd` resolves outside the folder it starts from.",
            );
        }
    }
    true
}

fn remote_valid(entry: &Map<String, Value>, report: &mut Report, path: &str) -> bool {
    let skip = |report: &mut Report, code, message: &str| {
        report.error(code, path, "7.2.1", Effect::SkipServer, message);
        false
    };
    let url = match entry.get("url") {
        Some(Value::String(url)) if !url.is_empty() => url,
        _ => {
            return skip(
                report,
                "mcp_url_missing",
                "A remote server needs a `url` string.",
            )
        }
    };
    if let Some(problem) = url_problem(url) {
        return skip(report, "mcp_url_invalid", problem);
    }
    if let Some(headers) = entry.get("headers") {
        let Some(headers) = headers.as_object() else {
            return skip(
                report,
                "mcp_headers_invalid",
                "`headers` must be an object of strings.",
            );
        };
        let mut seen = BTreeSet::new();
        for (name, value) in headers {
            let Some(value) = value.as_str() else {
                return skip(
                    report,
                    "mcp_headers_invalid",
                    "`headers` must be an object of strings.",
                );
            };
            if !header_name_valid(name) || !header_value_valid(value) {
                return skip(
                    report,
                    "mcp_header_invalid",
                    "Each header needs a valid HTTP field name and a value without control characters.",
                );
            }
            if !seen.insert(name.to_ascii_lowercase()) {
                return skip(
                    report,
                    "mcp_header_duplicate",
                    "The same header name appears twice with different casing.",
                );
            }
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "authorization" | "proxy-authorization" | "cookie"
            ) {
                report.error(
                    "mcp_header_holds_credential",
                    path,
                    "7.2.1",
                    Effect::None,
                    format!("`{name}` carries a credential. Header values are package data anyone can read; the client handles authorization."),
                );
            } else if secret_name(name) {
                report.warning(
                    "mcp_header_may_hold_secret",
                    path,
                    "7.2.1",
                    format!("`{name}` looks like a credential. Header values are package data anyone can read; leave credentials to the client."),
                );
            } else if value.contains("${") {
                report.warning(
                    "mcp_header_placeholder",
                    path,
                    "7.2.1",
                    format!("`{name}` is sent as written: Agent Plugins does not expand variables in headers."),
                );
            }
        }
    }
    true
}

/// Why `url` is not an MCP endpoint URL the specification allows.
pub(crate) fn url_problem(url: &str) -> Option<&'static str> {
    let Some((scheme, rest)) = url.split_once("://") else {
        return Some("`url` must be an absolute http or https URL.");
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Some("`url` must be an absolute http or https URL.");
    }
    if url.contains('#') {
        return Some("`url` must not have a fragment.");
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() {
        return Some("`url` must name a host.");
    }
    if authority.contains('@') {
        return Some("`url` must not carry user information.");
    }
    if scheme == "http" && !loopback(authority) {
        return Some("Only localhost and loopback addresses may use http; use https.");
    }
    None
}

fn loopback(authority: &str) -> bool {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn header_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn header_value_valid(value: &str) -> bool {
    value
        .chars()
        .all(|character| character == '\t' || !character.is_control())
        && value.trim_matches([' ', '\t']).len() == value.len()
}

fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "authorization"
        || name == "proxy-authorization"
        || [
            "token", "secret", "password", "api_key", "api-key", "apikey",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}

/// The path after an exact placeholder, or `None` when `value` does not
/// start with it as a whole path segment.
fn placeholder_rest<'a>(value: &'a str, placeholder: &str) -> Option<&'a str> {
    let rest = value.strip_prefix(placeholder)?;
    if rest.is_empty() {
        Some("")
    } else {
        rest.strip_prefix('/')
    }
}

/// Whether a path below the plugin root stays inside it, both by its
/// components and, when it exists, after resolving symlinks.
fn package_path_inside(root: &Path, relative: &str) -> bool {
    if !lexically_inside(relative) {
        return false;
    }
    let target = root.join(relative);
    match target.canonicalize() {
        Ok(resolved) => resolved.starts_with(root),
        Err(_) => true,
    }
}

fn lexically_inside(relative: &str) -> bool {
    if relative.starts_with(['/', '\\']) || relative.contains(':') {
        return false;
    }
    let mut depth = 0usize;
    for part in relative.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return false,
            },
            _ => depth += 1,
        }
    }
    true
}

enum Read {
    Missing,
    Outside,
    NotFile,
    Unreadable,
    Text(String),
}

/// Reads a package file, following symlinks only while they stay inside the
/// plugin root, as the specification allows.
fn read_inside(root: &Path, relative: &Path) -> Read {
    let path = root.join(relative);
    if fs::symlink_metadata(&path).is_err() {
        return Read::Missing;
    }
    let Some(resolved) = resolve_inside(root, &path) else {
        return Read::Outside;
    };
    let Ok(metadata) = fs::metadata(&resolved) else {
        return Read::Unreadable;
    };
    if !metadata.is_file() {
        return Read::NotFile;
    }
    if metadata.len() > MAX_TEXT_BYTES {
        return Read::Unreadable;
    }
    match fs::read(&resolved).map(String::from_utf8) {
        Ok(Ok(text)) => Read::Text(text),
        _ => Read::Unreadable,
    }
}

fn resolve_inside(root: &Path, path: &Path) -> Option<PathBuf> {
    let resolved = path.canonicalize().ok()?;
    resolved.starts_with(root).then_some(resolved)
}

/// The version in an Agent Plugins schema identifier, such as `1.1.0` in
/// `https://agent-plugins.org/schemas/1.1.0/plugin.schema.json`.
fn declared_version<'a>(schema: &'a str, file: &str) -> Option<&'a str> {
    let version = schema
        .strip_prefix(SCHEMA_PREFIX)?
        .strip_suffix(file)?
        .strip_suffix('/')?;
    (!version.is_empty() && !version.contains('/')).then_some(version)
}

/// §5.5: 1-64 of `a-z0-9.-`, alphanumeric at both ends, no `--` or `..`.
pub(crate) fn valid_plugin_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !name.is_empty()
        && name.len() <= MAX_NAME
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && !name.contains("--")
        && !name.contains("..")
}

/// Whether a skill can travel in an Agent Plugins package as
/// `skills/<name>/`: a valid Agent Skills name and a description of 1-1024
/// characters.
pub(crate) fn portable_skill(name: Option<&str>, description: Option<&str>) -> bool {
    name.is_some_and(valid_skill_name)
        && description.is_some_and(|description| {
            !description.is_empty() && description.chars().count() <= MAX_SKILL_DESCRIPTION
        })
}

/// The Agent Skills name rule: 1-64 of `a-z0-9-`, no leading, trailing or
/// doubled hyphen.
fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
}

#[cfg(test)]
mod tests {
    use super::{declared_version, lexically_inside, url_problem, valid_plugin_name};

    #[test]
    fn plugin_names_follow_section_5_5() {
        for name in ["my-plugin", "acme.tools", "lint3r", "a"] {
            assert!(valid_plugin_name(name), "{name}");
        }
        for name in [
            "My-Plugin",
            "-start",
            "has--double",
            "too.many..dots",
            "",
            "end.",
        ] {
            assert!(!valid_plugin_name(name), "{name}");
        }
        assert!(!valid_plugin_name(&"a".repeat(65)));
    }

    #[test]
    fn urls_follow_section_7_2_1() {
        assert_eq!(url_problem("https://deploy.example.com/mcp"), None);
        assert_eq!(url_problem("http://localhost:3000/mcp"), None);
        assert_eq!(url_problem("http://127.0.0.1/mcp"), None);
        assert_eq!(url_problem("http://[::1]:8080/mcp"), None);
        for url in [
            "http://example.com/mcp",
            "https://user:pass@example.com/mcp",
            "https://example.com/mcp#frag",
            "ftp://example.com",
            "example.com/mcp",
            "https:///mcp",
        ] {
            assert!(url_problem(url).is_some(), "{url}");
        }
    }

    #[test]
    fn relative_paths_stay_inside() {
        assert!(lexically_inside("bin/server"));
        assert!(lexically_inside("a/../b"));
        assert!(!lexically_inside("../bin/server"));
        assert!(!lexically_inside("a/../../b"));
        assert!(!lexically_inside("/etc"));
    }

    #[test]
    fn schema_versions_are_read_from_the_identifier() {
        assert_eq!(
            declared_version(
                "https://agent-plugins.org/schemas/1.1.0/plugin.schema.json",
                "plugin.schema.json"
            ),
            Some("1.1.0")
        );
        assert_eq!(
            declared_version(
                "https://example.com/plugin.schema.json",
                "plugin.schema.json"
            ),
            None
        );
    }
}
