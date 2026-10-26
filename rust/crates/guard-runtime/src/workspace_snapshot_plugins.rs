//! Agent plugins a project ships, checked over the bytes a workspace snapshot
//! hashed.
//!
//! A Claude Code or Codex plugin (`.claude-plugin/plugin.json`,
//! `.codex-plugin/plugin.json`) or a Gemini CLI extension
//! (`gemini-extension.json`) can sit at any depth of a worktree, as in a
//! plugin marketplace repository. Once a developer installs it, its hooks run
//! on their own at session start or around each tool call, and its MCP
//! servers start with the agent. Every hook command runs the shared
//! `hook_config_risk` rules and every MCP server the shared `mcp_config_risk`
//! rules. A finding carries the rule's fixed wording, the root-relative path
//! of the file that holds the hook or server, and the hook event or server
//! name, never the command, its arguments or a URL.
//!
//! A plugin's hooks are its manifest's inline `hooks`, the files that field
//! names and `hooks/hooks.json` at the plugin root. Its MCP servers are the
//! manifest's inline `mcpServers`, the files that field names and `.mcp.json`
//! at the plugin root. A `.mcp.json` at the worktree root is the project MCP
//! configuration the MCP check already reads, so it is left to that check.
//!
//! A manifest or referenced file the scan could not read in full leaves it
//! incomplete, as does a reference that leaves the plugin root, a reference
//! to a file the scan does not keep (anything but a `hooks/*.json` or a
//! `.mcp.json`), or a link or special file where a plugin could be. Plugins
//! listed inline in a marketplace file are not read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use guard_command::hook_config_risk::{detect_hook_config_risk, HookConfigRule};
use guard_command::jsonc::loads_jsonc;
use guard_command::mcp_config_risk::{detect_mcp_config_risk, McpConfigRule};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::hooks::{event_commands, stored_event, MAX_COMMAND_BYTES};
use super::skills::walked;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-plugins.v1";
/// Moves whenever the files read or a rule set changes, so a stored result
/// names what produced it.
pub(super) const DETECTOR_VERSION: &str = "plugin-manifest-v1";
pub(super) const MAX_PLUGIN_FINDINGS: usize = 200;
/// Larger than any hand-written manifest or plugin configuration.
const MAX_FILE_BYTES: usize = 1024 * 1024;
/// Manifests and plugin configuration files kept from one walk.
const MAX_KEPT_FILES: usize = 512;
const MAX_KEPT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PLUGINS: usize = 256;
const MAX_COMMANDS: usize = 512;
const MAX_SERVERS: usize = 512;
const MAX_ARGS: usize = 256;
const MAX_SERVER_TEXT: usize = 8 * 1024;
const FINDING_ID_HEX_CHARS: usize = 32;
const MANIFEST_DIRECTORIES: [&str; 2] = [".claude-plugin", ".codex-plugin"];
const MANIFEST_FILE: &str = "plugin.json";
const EXTENSION_FILE: &str = "gemini-extension.json";
const HOOKS_DIRECTORY: &str = "hooks";
const DEFAULT_HOOKS: &str = "hooks/hooks.json";
const MCP_FILE: &str = ".mcp.json";
/// Fields that name a remote MCP server's endpoint.
const URL_FIELDS: [&str; 3] = ["url", "httpUrl", "serverUrl"];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Hook,
    McpServer,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Hook => "hook",
            Kind::McpServer => "mcp_server",
        }
    }
}

/// A manifest or plugin configuration file as the walk left it.
enum Kept {
    Text(String),
    Oversize,
    NotText,
    Unread,
}

/// The fixed wording both rule sets share.
struct Rule {
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    confidence: &'static str,
    title: &'static str,
    reason: &'static str,
    false_positive_hint: Option<&'static str>,
}

impl From<HookConfigRule> for Rule {
    fn from(rule: HookConfigRule) -> Self {
        let HookConfigRule {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        } = rule;
        Self {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        }
    }
}

impl From<McpConfigRule> for Rule {
    fn from(rule: McpConfigRule) -> Self {
        let McpConfigRule {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        } = rule;
        Self {
            id,
            category,
            severity,
            confidence,
            title,
            reason,
            false_positive_hint,
        }
    }
}

struct Finding {
    rule: Rule,
    path: String,
    kind: Kind,
    name: String,
}

#[derive(Default)]
pub(super) struct PluginScan {
    worktree_key: String,
    /// The worktree root as requested and as resolved, for link targets.
    roots: Vec<PathBuf>,
    kept: BTreeMap<String, Kept>,
    kept_bytes: usize,
    kept_cap_hit: bool,
    linked: usize,
    path_too_long: bool,
}

impl PluginScan {
    pub(super) fn new(worktree_key: &str, roots: &[&Path]) -> Self {
        Self {
            worktree_key: worktree_key.to_owned(),
            roots: roots.iter().map(|root| root.to_path_buf()).collect(),
            ..Self::default()
        }
    }

    /// Whether `relative` is a manifest or plugin configuration file this
    /// scan must keep.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if !is_kept(relative) {
            return false;
        }
        if relative.len() > super::secrets::MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// The snapshot left an admitted file unread (oversize, byte budget,
    /// unreadable or unstable).
    pub(super) fn left_unread(&mut self, relative: &str) {
        self.keep(relative, Kept::Unread);
    }

    /// The snapshot did not follow a special file at `relative`.
    pub(super) fn left_special(&mut self, relative: &str) {
        if may_hold_plugin(relative) {
            self.linked += 1;
        }
    }

    /// The snapshot did not follow the symlink at `relative` to `target`.
    /// Plugins nest at any depth, so a link the walk cannot see through could
    /// hide one too.
    pub(super) fn left_link(&mut self, relative: &str, target: Option<&Path>) {
        if may_hold_plugin(relative)
            || !target.is_some_and(|target| walked(&self.roots, relative, target))
        {
            self.linked += 1;
        }
    }

    /// Keep the exact bytes hashed for `relative` until the walk ends, when
    /// every plugin's manifest and the files it names are known.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        let kept = if content.len() > MAX_FILE_BYTES {
            Kept::Oversize
        } else if self.kept_bytes + content.len() > MAX_KEPT_BYTES {
            Kept::Unread
        } else {
            match std::str::from_utf8(content) {
                Ok(text) => {
                    self.kept_bytes += content.len();
                    Kept::Text(text.to_owned())
                }
                Err(_) => Kept::NotText,
            }
        };
        self.keep(relative, kept);
    }

    fn keep(&mut self, relative: &str, kept: Kept) {
        if self.kept.len() >= MAX_KEPT_FILES {
            self.kept_cap_hit = true;
            return;
        }
        self.kept.insert(relative.to_owned(), kept);
    }

    /// `incomplete_reasons` names the snapshot limits that may have hidden a
    /// plugin from the walk; the scan is incomplete under any of them.
    pub(super) fn report(&self, incomplete_reasons: &[&str]) -> Value {
        let mut run = Run {
            worktree_key: &self.worktree_key,
            truncation: incomplete_reasons.iter().copied().collect(),
            ..Run::default()
        };
        for (hit, reason) in [
            (self.kept_cap_hit, "plugin_file_cap"),
            (self.linked > 0, "plugin_linked"),
            (self.path_too_long, "path_too_long"),
        ] {
            if hit {
                run.truncation.insert(reason);
            }
        }
        let mut checked: BTreeSet<(String, Kind)> = BTreeSet::new();
        for (path, kept) in &self.kept {
            let Some(root) = plugin_root(path) else {
                continue;
            };
            if run.plugins_scanned >= MAX_PLUGINS {
                run.truncation.insert("max_plugins");
                break;
            }
            let Some(manifest) = run.document(kept) else {
                continue;
            };
            run.plugins_scanned += 1;
            let mut targets = vec![(join(root, DEFAULT_HOOKS), Kind::Hook, false)];
            if !root.is_empty() {
                targets.push((join(root, MCP_FILE), Kind::McpServer, false));
            }
            for (field, kind) in [("hooks", Kind::Hook), ("mcpServers", Kind::McpServer)] {
                let references = match manifest.get(field) {
                    Some(inline @ Value::Object(_)) => {
                        run.check(path, kind, inline);
                        continue;
                    }
                    Some(Value::String(reference)) => vec![reference.as_str()],
                    Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
                    _ => continue,
                };
                for reference in references {
                    match resolve(root, reference) {
                        Some(target) => targets.push((target, kind, true)),
                        None => {
                            run.truncation.insert("plugin_reference_outside");
                        }
                    }
                }
            }
            for (target, kind, named) in targets {
                // The worktree's own `.mcp.json` belongs to the MCP check.
                if target == MCP_FILE || !checked.insert((target.clone(), kind)) {
                    continue;
                }
                match self.kept.get(&target) {
                    Some(kept) => {
                        if let Some(document) = run.document(kept) {
                            run.check(&target, kind, &document);
                        }
                    }
                    None if named && !is_kept(&target) => {
                        run.truncation.insert("plugin_reference_unread");
                    }
                    None => {}
                }
            }
        }
        run.into_value()
    }
}

#[derive(Default)]
struct Run<'a> {
    worktree_key: &'a str,
    truncation: BTreeSet<&'a str>,
    /// Keyed by finding id, so a rule repeated for one hook event or server is
    /// one finding.
    findings: BTreeMap<String, Finding>,
    plugins_scanned: usize,
    files_scanned: usize,
    commands_scanned: usize,
    servers_scanned: usize,
    oversize: usize,
    not_text: usize,
    unparsed: usize,
    unread: usize,
}

impl Run<'_> {
    fn document(&mut self, kept: &Kept) -> Option<Value> {
        let (count, reason) = match kept {
            Kept::Text(text) => match loads_jsonc(text) {
                Ok(document) => {
                    self.files_scanned += 1;
                    return Some(document);
                }
                Err(_) => (&mut self.unparsed, "plugin_file_unparsed"),
            },
            Kept::Oversize => (&mut self.oversize, "plugin_file_oversize"),
            Kept::NotText => (&mut self.not_text, "plugin_file_not_text"),
            Kept::Unread => (&mut self.unread, "plugin_file_unread"),
        };
        *count += 1;
        self.truncation.insert(reason);
        None
    }

    /// Check a hooks document or an MCP server map, inline in a manifest or
    /// as a file. Either may wrap its entries in `hooks` or `mcpServers`.
    fn check(&mut self, path: &str, kind: Kind, document: &Value) {
        let wrapper = match kind {
            Kind::Hook => "hooks",
            Kind::McpServer => "mcpServers",
        };
        let entries = match (document.get(wrapper), document) {
            (Some(Value::Object(entries)), _) | (None, Value::Object(entries)) => entries,
            _ => return,
        };
        match kind {
            Kind::Hook => self.check_hooks(path, entries),
            Kind::McpServer => self.check_servers(path, entries),
        }
    }

    fn check_hooks(&mut self, path: &str, events: &Map<String, Value>) {
        for command in event_commands(events) {
            if self.commands_scanned >= MAX_COMMANDS {
                self.truncation.insert("max_commands");
                return;
            }
            if command.bytes() > MAX_COMMAND_BYTES {
                self.truncation.insert("command_oversize");
                continue;
            }
            self.commands_scanned += 1;
            let event = stored_event(command.event);
            for rule in detect_hook_config_risk(command.text, command.args.as_deref()) {
                self.add(rule.into(), path, Kind::Hook, event);
            }
        }
    }

    fn check_servers(&mut self, path: &str, servers: &Map<String, Value>) {
        for (name, server) in servers {
            let Value::Object(fields) = server else {
                continue;
            };
            if self.servers_scanned >= MAX_SERVERS {
                self.truncation.insert("max_servers");
                return;
            }
            let command = fields.get("command").and_then(Value::as_str);
            let args: Vec<String> = fields
                .get("args")
                .and_then(Value::as_array)
                .map(|args| {
                    args.iter()
                        .filter_map(|arg| arg.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let url = URL_FIELDS
                .iter()
                .find_map(|field| fields.get(*field).and_then(Value::as_str));
            let oversize = args.len() > MAX_ARGS
                || command
                    .into_iter()
                    .chain(url)
                    .chain(args.iter().map(String::as_str))
                    .any(|text| text.len() > MAX_SERVER_TEXT);
            if oversize {
                self.truncation.insert("server_oversize");
                continue;
            }
            self.servers_scanned += 1;
            let name = stored_event(name);
            for rule in detect_mcp_config_risk(command, &args, url) {
                self.add(rule.into(), path, Kind::McpServer, name);
            }
        }
    }

    fn add(&mut self, rule: Rule, path: &str, kind: Kind, name: &str) {
        let finding_id = self.finding_id(rule.id, path, kind, name);
        if self.findings.contains_key(&finding_id) {
            return;
        }
        if self.findings.len() >= MAX_PLUGIN_FINDINGS {
            self.truncation.insert("max_findings");
            return;
        }
        self.findings.insert(
            finding_id,
            Finding {
                rule,
                path: path.to_owned(),
                kind,
                name: name.to_owned(),
            },
        );
    }

    fn finding_id(&self, rule_id: &str, path: &str, kind: Kind, name: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key,
            "plugin",
            kind.as_str(),
            rule_id,
            path,
            name,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\0");
        }
        let mut id = hex::encode(hasher.finalize());
        id.truncate(FINDING_ID_HEX_CHARS);
        id
    }

    fn into_value(self) -> Value {
        let mut findings: Vec<(&String, &Finding)> = self.findings.iter().collect();
        findings.sort_by(|(_, a), (_, b)| {
            (&a.path, a.kind, &a.name, a.rule.id).cmp(&(&b.path, b.kind, &b.name, b.rule.id))
        });
        let findings: Vec<Value> = findings
            .into_iter()
            .map(|(finding_id, finding)| {
                json!({
                    "finding_id": finding_id,
                    "rule_id": finding.rule.id,
                    "category": finding.rule.category,
                    "severity": finding.rule.severity,
                    "confidence": finding.rule.confidence,
                    "title": finding.rule.title,
                    "reason": finding.rule.reason,
                    "false_positive_hint": finding.rule.false_positive_hint,
                    "path": finding.path,
                    "kind": finding.kind.as_str(),
                    "name": finding.name,
                })
            })
            .collect();
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": DETECTOR_VERSION,
            "status": if self.truncation.is_empty() { "complete" } else { "incomplete" },
            "plugins_scanned": self.plugins_scanned,
            "files_scanned": self.files_scanned,
            "commands_scanned": self.commands_scanned,
            "servers_scanned": self.servers_scanned,
            "skipped": {
                "oversize": self.oversize,
                "not_text": self.not_text,
                "unparsed": self.unparsed,
                "unread": self.unread,
            },
            "truncation_reasons": self.truncation.into_iter().collect::<Vec<_>>(),
            "findings": findings,
        })
    }
}

/// The plugin root a manifest at `path` describes, or `None` when `path` is
/// not a manifest.
fn plugin_root(path: &str) -> Option<&str> {
    if let Some(directory) = path.strip_suffix(EXTENSION_FILE) {
        return (directory.is_empty() || directory.ends_with('/'))
            .then(|| directory.trim_end_matches('/'));
    }
    let directory = path.strip_suffix(MANIFEST_FILE)?.strip_suffix('/')?;
    let (root, name) = directory.rsplit_once('/').unwrap_or(("", directory));
    MANIFEST_DIRECTORIES.contains(&name).then_some(root)
}

/// Manifests, every `.mcp.json` below the worktree root and every JSON file
/// directly in a `hooks` directory: the files a plugin can hold hooks or MCP
/// servers in by default.
fn is_kept(path: &str) -> bool {
    plugin_root(path).is_some()
        || path.rsplit_once('/').is_some_and(|(directory, name)| {
            name == MCP_FILE
                || (name.ends_with(".json")
                    && (directory == HOOKS_DIRECTORY
                        || directory.ends_with(&format!("/{HOOKS_DIRECTORY}"))))
        })
}

/// Whether a link or special file at `relative` could stand in for a
/// manifest, a plugin configuration file or a directory that holds one.
fn may_hold_plugin(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    is_kept(relative) || MANIFEST_DIRECTORIES.contains(&name) || name == HOOKS_DIRECTORY
}

fn join(root: &str, relative: &str) -> String {
    if root.is_empty() {
        relative.to_owned()
    } else {
        format!("{root}/{relative}")
    }
}

/// The root-relative path a manifest reference names, or `None` when it is
/// absolute or leaves the plugin root.
fn resolve(root: &str, reference: &str) -> Option<String> {
    if reference.starts_with('/') || reference.contains('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(join(root, &parts.join("/")))
}
