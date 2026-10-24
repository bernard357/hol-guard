//! Runtime emitters: one plugin source, packaged for every runtime that can
//! load it.
//!
//! Emitters are pure. They return the files to write as an ordered plan, so
//! the output is identical for identical input and golden tests can compare
//! it without touching disk. MCP environment variables are emitted as
//! references in each runtime's own syntax; values are never carried.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::check::is_kebab;
use crate::model::{McpServer, Plugin};
use crate::walk;

/// The largest single file a package copies.
const MAX_COPY_BYTES: u64 = 5 * 1024 * 1024;
/// The most bytes one package may copy across all runtimes.
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4_000;
const MCP_REGISTRY_SCHEMA: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    ClaudeCode,
    Codex,
    GeminiCli,
    Cursor,
    Vscode,
    Opencode,
    McpRegistry,
    AgentSkills,
}

impl Runtime {
    pub const ALL: [Runtime; 8] = [
        Runtime::ClaudeCode,
        Runtime::Codex,
        Runtime::GeminiCli,
        Runtime::Cursor,
        Runtime::Vscode,
        Runtime::Opencode,
        Runtime::McpRegistry,
        Runtime::AgentSkills,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Runtime::ClaudeCode => "claude-code",
            Runtime::Codex => "codex",
            Runtime::GeminiCli => "gemini-cli",
            Runtime::Cursor => "cursor",
            Runtime::Vscode => "vscode",
            Runtime::Opencode => "opencode",
            Runtime::McpRegistry => "mcp-registry",
            Runtime::AgentSkills => "agent-skills",
        }
    }

    pub fn parse(value: &str) -> Option<Runtime> {
        Runtime::ALL
            .into_iter()
            .find(|runtime| runtime.id() == value)
    }
}

/// One file of a package, relative to the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub path: String,
    pub content: Vec<u8>,
}

pub fn supports(runtime: Runtime, plugin: &Plugin) -> bool {
    let named = plugin.name.as_deref().is_some_and(is_kebab);
    match runtime {
        Runtime::ClaudeCode | Runtime::Codex => {
            named
                && (!plugin.skills.is_empty()
                    || !plugin.mcp_servers.is_empty()
                    || has_claude_only(plugin))
        }
        Runtime::GeminiCli => {
            named && (!plugin.mcp_servers.is_empty() || plugin.context_file.is_some())
        }
        Runtime::Cursor | Runtime::Vscode | Runtime::Opencode => !plugin.mcp_servers.is_empty(),
        Runtime::McpRegistry => registry_document(plugin).is_some(),
        Runtime::AgentSkills => plugin
            .skills
            .iter()
            .any(|skill| skill_slug(skill).is_some()),
    }
}

fn has_claude_only(plugin: &Plugin) -> bool {
    !plugin.commands.is_empty() || !plugin.agents.is_empty() || plugin.hooks.is_some()
}

/// The components a runtime has no place for, among those the plugin has.
pub fn dropped(runtime: Runtime, plugin: &Plugin) -> Vec<&'static str> {
    let present = [
        ("skills", !plugin.skills.is_empty()),
        ("mcp_servers", !plugin.mcp_servers.is_empty()),
        ("commands", !plugin.commands.is_empty()),
        ("agents", !plugin.agents.is_empty()),
        ("hooks", plugin.hooks.is_some()),
        ("context_file", plugin.context_file.is_some()),
    ];
    let kept: &[&str] = match runtime {
        Runtime::ClaudeCode => &["skills", "mcp_servers", "commands", "agents", "hooks"],
        Runtime::Codex => &["skills", "mcp_servers"],
        Runtime::GeminiCli => &["mcp_servers", "context_file"],
        Runtime::Cursor | Runtime::Vscode | Runtime::Opencode | Runtime::McpRegistry => {
            &["mcp_servers"]
        }
        Runtime::AgentSkills => &["skills"],
    };
    present
        .into_iter()
        .filter(|(name, has)| *has && !kept.contains(name))
        .map(|(name, _)| name)
        .collect()
}

/// The files to write for each runtime, under `<runtime>/`, in path order.
pub fn plan(root: &Path, plugin: &Plugin, runtimes: &[Runtime]) -> Result<Vec<Output>, String> {
    let mut outputs = BTreeMap::new();
    let mut budget = Budget::default();
    for &runtime in runtimes {
        if !supports(runtime, plugin) {
            continue;
        }
        let prefix = runtime.id();
        let mut put_json = |path: &str, value: Value| {
            outputs.insert(format!("{prefix}/{path}"), json_bytes(&value));
        };
        match runtime {
            Runtime::ClaudeCode => {
                put_json(".claude-plugin/plugin.json", manifest(plugin, None));
                if !plugin.mcp_servers.is_empty() {
                    put_json(
                        ".mcp.json",
                        json!({"mcpServers": servers(plugin, Syntax::Claude)}),
                    );
                }
            }
            Runtime::Codex => {
                let mut extra = Map::new();
                if plugin
                    .skills
                    .iter()
                    .any(|skill| skill_slug(skill).is_some())
                {
                    extra.insert("skills".into(), json!("./skills/"));
                }
                if !plugin.mcp_servers.is_empty() {
                    extra.insert("mcpServers".into(), json!("./.mcp.json"));
                    put_json(
                        ".mcp.json",
                        json!({"mcpServers": servers(plugin, Syntax::Claude)}),
                    );
                }
                put_json(".codex-plugin/plugin.json", manifest(plugin, Some(extra)));
            }
            Runtime::GeminiCli => {
                let mut extension = Map::new();
                extension.insert("name".into(), json!(plugin.name));
                extension.insert(
                    "version".into(),
                    json!(plugin.version.as_deref().unwrap_or("0.1.0")),
                );
                if let Some(description) = &plugin.description {
                    extension.insert("description".into(), json!(description));
                }
                if !plugin.mcp_servers.is_empty() {
                    extension.insert("mcpServers".into(), servers(plugin, Syntax::Gemini));
                }
                if plugin.context_file.is_some() {
                    extension.insert("contextFileName".into(), json!("GEMINI.md"));
                }
                put_json("gemini-extension.json", Value::Object(extension));
            }
            Runtime::Cursor => put_json(
                ".cursor/mcp.json",
                json!({"mcpServers": servers(plugin, Syntax::Cursor)}),
            ),
            Runtime::Vscode => put_json(
                ".vscode/mcp.json",
                json!({"servers": servers(plugin, Syntax::Vscode)}),
            ),
            Runtime::Opencode => put_json(
                "opencode.json",
                json!({"$schema": "https://opencode.ai/config.json", "mcp": servers(plugin, Syntax::Opencode)}),
            ),
            Runtime::McpRegistry => {
                if let Some(document) = registry_document(plugin) {
                    put_json("server.json", document);
                }
            }
            Runtime::AgentSkills => {}
        }
        let copies = copies(runtime, root, plugin, &mut budget)?;
        for (path, content) in copies {
            outputs.insert(format!("{prefix}/{path}"), content);
        }
    }
    Ok(outputs
        .into_iter()
        .map(|(path, content)| Output { path, content })
        .collect())
}

#[derive(Default)]
struct Budget {
    files: usize,
    bytes: u64,
}

/// Source files a runtime carries unchanged: skill folders, Claude Code
/// commands, agents and hooks, and the Gemini context file.
fn copies(
    runtime: Runtime,
    root: &Path,
    plugin: &Plugin,
    budget: &mut Budget,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut found = Vec::new();
    let with_skills = matches!(
        runtime,
        Runtime::ClaudeCode | Runtime::Codex | Runtime::AgentSkills
    );
    if with_skills {
        for skill in &plugin.skills {
            let Some(slug) = skill_slug(skill) else {
                continue;
            };
            let dir = root.join(&skill.dir);
            if skill.dir.is_empty() {
                // A SKILL.md at the repository root travels alone.
                found.push((dir.join("SKILL.md"), format!("skills/{slug}/SKILL.md")));
                continue;
            }
            for file in walk::files(&dir)? {
                found.push((
                    dir.join(&file),
                    format!("skills/{slug}/{}", walk::display(&file)),
                ));
            }
        }
    }
    if runtime == Runtime::ClaudeCode {
        for path in plugin.commands.iter().chain(&plugin.agents) {
            let source = Path::new(path);
            let folder = if plugin.commands.contains(path) {
                "commands"
            } else {
                "agents"
            };
            if let Some(name) = source.file_name() {
                found.push((
                    root.join(source),
                    format!("{folder}/{}", name.to_string_lossy()),
                ));
            }
        }
        if let Some(hooks) = &plugin.hooks {
            // Hook commands usually call scripts beside them, so the whole
            // hooks folder travels with hooks.json.
            let dir = root
                .join(hooks)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            for file in walk::files(&dir)? {
                found.push((dir.join(&file), format!("hooks/{}", walk::display(&file))));
            }
        }
    }
    if runtime == Runtime::GeminiCli {
        if let Some(context) = &plugin.context_file {
            let base = if plugin.base.is_empty() {
                String::new()
            } else {
                format!("{}/", plugin.base)
            };
            let source = if context.starts_with(&base) {
                context.clone()
            } else {
                format!("{base}{context}")
            };
            found.push((root.join(source), "GEMINI.md".to_owned()));
        }
    }
    let mut copied = Vec::new();
    for (source, target) in found {
        let Some(content) = walk::read_bytes(&source, MAX_COPY_BYTES) else {
            continue;
        };
        budget.files += 1;
        budget.bytes += content.len() as u64;
        if budget.files > MAX_FILES || budget.bytes > MAX_TOTAL_BYTES {
            return Err("plugin_kit_package_too_large".to_owned());
        }
        copied.push((target, content));
    }
    Ok(copied)
}

/// The folder name a skill is packaged under: its kebab-case name, else its
/// source folder name when that is kebab-case.
pub(crate) fn skill_slug(skill: &crate::model::Skill) -> Option<String> {
    if let Some(name) = skill
        .name
        .as_deref()
        .filter(|name| is_kebab(name) && name.len() <= 64)
    {
        return Some(name.to_owned());
    }
    let folder = Path::new(&skill.dir).file_name()?.to_str()?;
    is_kebab(folder).then(|| folder.to_owned())
}

fn manifest(plugin: &Plugin, extra: Option<Map<String, Value>>) -> Value {
    let mut manifest = Map::new();
    manifest.insert("name".into(), json!(plugin.name));
    for (key, value) in [
        ("version", &plugin.version),
        ("description", &plugin.description),
        ("homepage", &plugin.homepage),
        ("repository", &plugin.repository),
        ("license", &plugin.license),
    ] {
        if let Some(value) = value {
            manifest.insert(key.into(), json!(value));
        }
    }
    if let Some(author) = &plugin.author {
        manifest.insert("author".into(), json!({"name": author}));
    }
    if !plugin.keywords.is_empty() {
        manifest.insert("keywords".into(), json!(plugin.keywords));
    }
    manifest.extend(extra.unwrap_or_default());
    Value::Object(manifest)
}

#[derive(Clone, Copy)]
enum Syntax {
    Claude,
    Gemini,
    Cursor,
    Vscode,
    Opencode,
}

fn env_reference(syntax: Syntax, name: &str) -> String {
    match syntax {
        Syntax::Claude => format!("${{{name}}}"),
        Syntax::Gemini => format!("${name}"),
        Syntax::Cursor | Syntax::Vscode => format!("${{env:{name}}}"),
        Syntax::Opencode => format!("{{env:{name}}}"),
    }
}

fn servers(plugin: &Plugin, syntax: Syntax) -> Value {
    let mut entries = Map::new();
    for (name, server) in &plugin.mcp_servers {
        if let Some(entry) = server_value(server, syntax) {
            entries.insert(name.clone(), entry);
        }
    }
    Value::Object(entries)
}

fn server_value(server: &McpServer, syntax: Syntax) -> Option<Value> {
    let env: Map<String, Value> = server
        .env
        .iter()
        .map(|name| (name.clone(), json!(env_reference(syntax, name))))
        .collect();
    let mut entry = Map::new();
    if let Some(command) = &server.command {
        match syntax {
            Syntax::Opencode => {
                let mut command_line = vec![command.clone()];
                command_line.extend(server.args.iter().cloned());
                entry.insert("type".into(), json!("local"));
                entry.insert("command".into(), json!(command_line));
                if !env.is_empty() {
                    entry.insert("environment".into(), Value::Object(env));
                }
                return Some(Value::Object(entry));
            }
            Syntax::Vscode => {
                entry.insert("type".into(), json!("stdio"));
            }
            _ => {}
        }
        entry.insert("command".into(), json!(command));
        if !server.args.is_empty() {
            entry.insert("args".into(), json!(server.args));
        }
        if !env.is_empty() {
            entry.insert("env".into(), Value::Object(env));
        }
    } else {
        let url = server.url.as_ref()?;
        match syntax {
            Syntax::Claude | Syntax::Vscode => {
                entry.insert("type".into(), json!("http"));
                entry.insert("url".into(), json!(url));
            }
            Syntax::Gemini => {
                entry.insert("httpUrl".into(), json!(url));
            }
            Syntax::Cursor => {
                entry.insert("url".into(), json!(url));
            }
            Syntax::Opencode => {
                entry.insert("type".into(), json!("remote"));
                entry.insert("url".into(), json!(url));
            }
        }
    }
    Some(Value::Object(entry))
}

/// An MCP Registry `server.json`: the repository's own when it has one, or
/// one generated for a single remote server on GitHub. Anything else would
/// need a package identity the Kit cannot infer, so it is not emitted.
fn registry_document(plugin: &Plugin) -> Option<Value> {
    if let Some(document) = &plugin.registry_server {
        return Some(document.clone());
    }
    let (_, server) = plugin
        .mcp_servers
        .iter()
        .next()
        .filter(|_| plugin.mcp_servers.len() == 1)?;
    let url = server.url.as_ref().filter(|_| server.command.is_none())?;
    let repository = plugin.github_repository()?;
    let name = plugin.name.as_deref().filter(|name| is_kebab(name))?;
    let (owner, _) = repository.split_once('/')?;
    Some(json!({
        "$schema": MCP_REGISTRY_SCHEMA,
        "name": format!("io.github.{owner}/{name}"),
        "description": plugin.description.as_deref()?,
        "version": plugin.version.as_deref()?,
        "repository": {"url": format!("https://github.com/{repository}"), "source": "github"},
        "remotes": [{"type": "streamable-http", "url": url}],
    }))
}

pub(crate) fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// A digest of the source files a package was built from: each relative path
/// and the SHA-256 of its bytes, in path order.
pub fn source_digest(root: &Path, inputs: &[std::path::PathBuf]) -> String {
    let mut hasher = Sha256::new();
    for input in inputs {
        let content = walk::read_bytes(&root.join(input), MAX_COPY_BYTES).unwrap_or_default();
        hasher.update(walk::display(input).as_bytes());
        hasher.update([0]);
        hasher.update(hex::encode(Sha256::digest(&content)).as_bytes());
        hasher.update([b'\n']);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{env_reference, Runtime, Syntax};

    #[test]
    fn runtime_ids_round_trip() {
        for runtime in Runtime::ALL {
            assert_eq!(Runtime::parse(runtime.id()), Some(runtime));
        }
        assert_eq!(Runtime::parse("windsurf"), None);
    }

    #[test]
    fn env_references_use_each_runtime_syntax() {
        assert_eq!(env_reference(Syntax::Claude, "API_KEY"), "${API_KEY}");
        assert_eq!(env_reference(Syntax::Gemini, "API_KEY"), "$API_KEY");
        assert_eq!(env_reference(Syntax::Vscode, "API_KEY"), "${env:API_KEY}");
        assert_eq!(env_reference(Syntax::Opencode, "API_KEY"), "{env:API_KEY}");
    }
}
