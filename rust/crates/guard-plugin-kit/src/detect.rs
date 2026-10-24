//! Source detection: which plugin formats a repository already ships, and the
//! runtime-neutral [`Plugin`] they describe.
//!
//! The markers match the scanner's ecosystem adapters
//! (`.claude-plugin/plugin.json`, `.codex-plugin/plugin.json`,
//! `gemini-extension.json`, marketplace manifests, `SKILL.md`) and add the MCP
//! Registry `server.json`. MCP server entries read `command`, `args`, `env`
//! and the remote aliases `url`, `httpUrl` and `serverUrl`, as the host
//! adapter detection does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::model::{Diagnostic, Marketplace, McpServer, Plugin, Skill, Source, SourceKind};
use crate::walk;

pub struct Detection {
    pub sources: Vec<Source>,
    pub plugin: Plugin,
    pub diagnostics: Vec<Diagnostic>,
    /// Every file the detection read, for the provenance digest.
    pub inputs: Vec<PathBuf>,
    /// `(server, variable, is_literal)` for each MCP env entry. Values are
    /// never kept; only whether one is a literal rather than a reference.
    pub raw_env: Vec<(String, String, bool)>,
}

pub fn detect(root: &Path) -> Result<Detection, String> {
    let files = walk::files(root)?;
    let mut sources = Vec::new();
    for file in &files {
        if let Some(kind) = classify(file) {
            sources.push(Source {
                kind,
                path: walk::display(file),
            });
        }
    }
    sources.sort_by(|left, right| left.kind.cmp(&right.kind).then(left.path.cmp(&right.path)));

    let mut diagnostics = Vec::new();
    let mut documents: BTreeMap<String, Value> = BTreeMap::new();
    for source in &sources {
        if source.kind == SourceKind::AgentSkill {
            continue;
        }
        match walk::read_text(&root.join(&source.path)).map(|text| serde_json::from_str(&text)) {
            Some(Ok(value @ Value::Object(_))) => {
                documents.insert(source.path.clone(), value);
            }
            _ => diagnostics.push(Diagnostic::error(
                "manifest_invalid_json",
                &source.path,
                "The manifest is not a JSON object.",
            )),
        }
    }

    let base = plugin_base(&sources);
    let mut plugin = Plugin {
        base: base.clone(),
        ..Plugin::default()
    };
    for source in sources.iter().filter(|source| source.kind.is_plugin_root()) {
        if source_base(source) != base {
            continue;
        }
        if let Some(document) = documents.get(&source.path) {
            merge_metadata(&mut plugin, source.kind, document);
        }
    }
    let mut inputs: Vec<PathBuf> = sources
        .iter()
        .map(|source| PathBuf::from(&source.path))
        .collect();
    let mut raw_env = Vec::new();

    for source in &sources {
        let Some(document) = documents.get(&source.path) else {
            if source.kind == SourceKind::AgentSkill {
                plugin
                    .skills
                    .push(read_skill(root, source, &mut diagnostics));
            }
            continue;
        };
        match source.kind {
            SourceKind::McpConfig | SourceKind::ClaudePlugin | SourceKind::GeminiExtension
                if source_base(source) == base =>
            {
                collect_servers(
                    &mut plugin.mcp_servers,
                    &mut raw_env,
                    document.get("mcpServers"),
                );
            }
            SourceKind::McpServer if source_base(source) == base => {
                registry_server(&mut plugin, document);
            }
            SourceKind::ClaudeMarketplace | SourceKind::CodexMarketplace => {
                if plugin.marketplace.is_none() {
                    plugin.marketplace = Some(marketplace(source, document, &mut diagnostics));
                }
            }
            _ => {}
        }
    }
    plugin
        .skills
        .sort_by(|left, right| left.dir.cmp(&right.dir));

    let join = |name: &str| {
        if base.is_empty() {
            name.to_owned()
        } else {
            format!("{base}/{name}")
        }
    };
    for file in &files {
        let path = walk::display(file);
        if let Some(rest) = path.strip_prefix(&join("commands/")) {
            if !rest.contains('/') && rest.ends_with(".md") {
                plugin.commands.push(path.clone());
                inputs.push(file.clone());
            }
        } else if let Some(rest) = path.strip_prefix(&join("agents/")) {
            if !rest.contains('/') && rest.ends_with(".md") {
                plugin.agents.push(path.clone());
                inputs.push(file.clone());
            }
        } else if path == join("hooks/hooks.json") {
            plugin.hooks = Some(path.clone());
            inputs.push(file.clone());
        } else if path == join("GEMINI.md") && plugin.context_file.is_none() {
            plugin.context_file = Some(path.clone());
            inputs.push(file.clone());
        }
    }
    if plugin.repository.is_none() {
        plugin.repository =
            package_repository(root, &base, &mut inputs).or_else(|| git_origin(root));
    }
    if plugin.name.is_none() && plugin.base.is_empty() && !plugin.skills.is_empty() {
        plugin.name = root
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase());
    }
    inputs.sort();
    inputs.dedup();
    Ok(Detection {
        sources,
        plugin,
        diagnostics,
        inputs,
        raw_env,
    })
}

fn classify(file: &Path) -> Option<SourceKind> {
    let name = file.file_name()?.to_str()?;
    let parent = file
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let grandparent = file
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("");
    match (name, parent) {
        ("plugin.json", ".claude-plugin") => Some(SourceKind::ClaudePlugin),
        ("marketplace.json", ".claude-plugin") => Some(SourceKind::ClaudeMarketplace),
        ("plugin.json", ".codex-plugin") => Some(SourceKind::CodexPlugin),
        ("marketplace.json", "plugins") if grandparent == ".agents" => {
            Some(SourceKind::CodexMarketplace)
        }
        ("gemini-extension.json", _) => Some(SourceKind::GeminiExtension),
        ("server.json", _) => Some(SourceKind::McpServer),
        (".mcp.json", _) => Some(SourceKind::McpConfig),
        ("SKILL.md", _) => Some(SourceKind::AgentSkill),
        _ => None,
    }
}

/// The directory a source's manifest describes ("" for the repository root).
fn source_base(source: &Source) -> String {
    let path = Path::new(&source.path);
    let parent = path.parent().unwrap_or(Path::new(""));
    let base = match source.kind {
        SourceKind::ClaudePlugin | SourceKind::CodexPlugin | SourceKind::ClaudeMarketplace => {
            parent.parent().unwrap_or(Path::new(""))
        }
        SourceKind::CodexMarketplace => parent
            .parent()
            .and_then(Path::parent)
            .unwrap_or(Path::new("")),
        _ => parent,
    };
    walk::display(base)
}

/// The shallowest plugin root; a tie goes to the earlier [`SourceKind`].
fn plugin_base(sources: &[Source]) -> String {
    sources
        .iter()
        .filter(|source| source.kind.is_plugin_root())
        .map(source_base)
        .min_by_key(|base| {
            (
                if base.is_empty() {
                    0
                } else {
                    base.split('/').count()
                },
                base.clone(),
            )
        })
        .unwrap_or_default()
}

fn text(document: &Value, key: &str) -> Option<String> {
    document
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn merge_metadata(plugin: &mut Plugin, kind: SourceKind, document: &Value) {
    let fill = |slot: &mut Option<String>, value: Option<String>| {
        if slot.is_none() {
            *slot = value;
        }
    };
    let name = if kind == SourceKind::McpServer {
        // MCP Registry names are reverse-DNS (`io.github.owner/server`); the
        // plugin name is the last segment.
        text(document, "name").map(|name| name.rsplit('/').next().unwrap_or(&name).to_owned())
    } else {
        text(document, "name")
    };
    fill(&mut plugin.name, name);
    fill(&mut plugin.version, text(document, "version"));
    fill(&mut plugin.description, text(document, "description"));
    fill(
        &mut plugin.homepage,
        text(document, "homepage").or_else(|| text(document, "websiteUrl")),
    );
    fill(&mut plugin.license, text(document, "license"));
    let author = match document.get("author") {
        Some(Value::String(name)) => Some(name.trim().to_owned()).filter(|name| !name.is_empty()),
        Some(Value::Object(author)) => author
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        _ => None,
    };
    fill(&mut plugin.author, author);
    let repository = match document.get("repository") {
        Some(Value::String(url)) => Some(url.trim().to_owned()),
        Some(Value::Object(repository)) => repository
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    };
    fill(
        &mut plugin.repository,
        repository.filter(|url| !url.is_empty()),
    );
    if plugin.keywords.is_empty() {
        if let Some(Value::Array(keywords)) = document.get("keywords") {
            plugin.keywords = keywords
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(32)
                .collect();
        }
    }
    if kind == SourceKind::GeminiExtension && plugin.context_file.is_none() {
        plugin.context_file = text(document, "contextFileName");
    }
}

fn collect_servers(
    servers: &mut BTreeMap<String, McpServer>,
    raw_env: &mut Vec<(String, String, bool)>,
    value: Option<&Value>,
) {
    let Some(Value::Object(entries)) = value else {
        return;
    };
    for (name, config) in entries {
        let Value::Object(config) = config else {
            continue;
        };
        if let Some(Value::Object(env)) = config.get("env") {
            for (key, value) in env {
                let literal = value.as_str().map(str::trim).is_some_and(|value| {
                    !value.is_empty() && !value.starts_with('$') && !value.starts_with('<')
                });
                raw_env.push((name.clone(), key.clone(), literal));
            }
        }
        servers
            .entry(name.clone())
            .or_insert_with(|| server_entry(config));
    }
}

fn server_entry(config: &Map<String, Value>) -> McpServer {
    let string = |key: &str| {
        config
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let mut env: Vec<String> = match config.get("env") {
        Some(Value::Object(env)) => env.keys().cloned().collect(),
        _ => Vec::new(),
    };
    env.sort();
    McpServer {
        command: string("command"),
        args: match config.get("args") {
            Some(Value::Array(args)) => args
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => Vec::new(),
        },
        url: string("url")
            .or_else(|| string("httpUrl"))
            .or_else(|| string("serverUrl")),
        env,
    }
}

/// An MCP Registry `server.json` becomes one server: its first package as a
/// local command, else its first remote.
fn registry_server(plugin: &mut Plugin, document: &Value) {
    plugin.registry_server = Some(document.clone());
    let Some(name) = plugin.name.clone().or_else(|| text(document, "name")) else {
        return;
    };
    let package = document
        .get("packages")
        .and_then(Value::as_array)
        .and_then(|packages| packages.first());
    let remote = document
        .get("remotes")
        .and_then(Value::as_array)
        .and_then(|remotes| remotes.first());
    let server = if let Some(package) = package {
        let identifier = text(package, "identifier").unwrap_or_default();
        let version = text(package, "version");
        let (command, args) = match text(package, "registryType").as_deref() {
            Some("npm") => (
                "npx",
                vec![
                    "-y".to_owned(),
                    version.map_or(identifier.clone(), |version| {
                        format!("{identifier}@{version}")
                    }),
                ],
            ),
            Some("pypi") => (
                "uvx",
                vec![version.map_or(identifier.clone(), |version| {
                    format!("{identifier}=={version}")
                })],
            ),
            Some("oci") => (
                "docker",
                vec![
                    "run".to_owned(),
                    "-i".to_owned(),
                    "--rm".to_owned(),
                    identifier.clone(),
                ],
            ),
            _ => return,
        };
        let mut env: Vec<String> = package
            .get("environmentVariables")
            .and_then(Value::as_array)
            .map(|variables| {
                variables
                    .iter()
                    .filter_map(|variable| text(variable, "name"))
                    .collect()
            })
            .unwrap_or_default();
        env.sort();
        McpServer {
            command: Some(command.to_owned()),
            args,
            url: None,
            env,
        }
    } else if let Some(url) = remote.and_then(|remote| text(remote, "url")) {
        McpServer {
            url: Some(url),
            ..McpServer::default()
        }
    } else {
        return;
    };
    plugin.mcp_servers.entry(name).or_insert(server);
}

fn marketplace(
    source: &Source,
    document: &Value,
    diagnostics: &mut Vec<Diagnostic>,
) -> Marketplace {
    let mut plugins = Vec::new();
    if let Some(Value::Array(entries)) = document.get("plugins") {
        for (index, entry) in entries.iter().enumerate() {
            match text(entry, "name") {
                Some(name) if entry.get("source").is_some() => plugins.push(name),
                _ => diagnostics.push(Diagnostic::error(
                    "marketplace_entry_incomplete",
                    &source.path,
                    format!("plugins[{index}] needs a name and a source."),
                )),
            }
        }
    }
    Marketplace {
        name: text(document, "name"),
        path: source.path.clone(),
        plugins,
    }
}

fn read_skill(root: &Path, source: &Source, diagnostics: &mut Vec<Diagnostic>) -> Skill {
    let dir = Path::new(&source.path)
        .parent()
        .map(walk::display)
        .unwrap_or_default();
    let fields = walk::read_text(&root.join(&source.path))
        .map(|text| frontmatter(&text))
        .unwrap_or_default();
    if fields.is_empty() {
        diagnostics.push(Diagnostic::error(
            "skill_frontmatter_missing",
            &source.path,
            "SKILL.md needs YAML frontmatter with name and description.",
        ));
    }
    Skill {
        name: fields.get("name").cloned(),
        description: fields.get("description").cloned(),
        dir,
    }
}

/// The scalar `key: value` fields of a leading `---` block. Folded (`>`) and
/// literal (`|`) scalars are joined into one line.
pub(crate) fn frontmatter(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(body) = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))
    else {
        return fields;
    };
    let mut lines = body.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_end() == "---" {
            return fields;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_owned();
        let mut value = value.trim().to_owned();
        if matches!(value.as_str(), ">" | "|" | ">-" | "|-" | ">+" | "|+") {
            let mut parts = Vec::new();
            while let Some(next) = lines.peek() {
                if !next.starts_with([' ', '\t']) && !next.trim().is_empty() {
                    break;
                }
                parts.push(next.trim().to_owned());
                lines.next();
            }
            value = parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
        }
        let unquoted = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .map(str::to_owned)
            .unwrap_or(value);
        if !key.is_empty() && !unquoted.is_empty() {
            fields.insert(key, unquoted);
        }
    }
    // An unterminated block is not frontmatter.
    BTreeMap::new()
}

/// The `repository` of a `package.json` beside the plugin root, which npm
/// packaged MCP servers and extensions usually set.
fn package_repository(root: &Path, base: &str, inputs: &mut Vec<PathBuf>) -> Option<String> {
    let path = Path::new(base).join("package.json");
    let document: Value = serde_json::from_str(&walk::read_text(&root.join(&path))?).ok()?;
    let url = match document.get("repository")? {
        Value::String(url) => url.clone(),
        Value::Object(repository) => repository.get("url")?.as_str()?.to_owned(),
        _ => return None,
    };
    let full_name = crate::model::github_full_name(&url)?;
    inputs.push(path);
    Some(format!("https://github.com/{full_name}"))
}

/// The `origin` remote from `.git/config`, read as text; Git is never run.
fn git_origin(root: &Path) -> Option<String> {
    let config = walk::read_text(&root.join(".git").join("config"))?;
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "url" {
                    return crate::model::github_full_name(value.trim())
                        .map(|full_name| format!("https://github.com/{full_name}"));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::frontmatter;

    #[test]
    fn frontmatter_reads_scalars_and_folded_text() {
        let fields = frontmatter(
            "---\nname: pdf-tools\ndescription: >\n  Fill PDF forms\n  and extract text.\nlicense: \"MIT\"\n---\n# Body\n",
        );
        assert_eq!(fields["name"], "pdf-tools");
        assert_eq!(fields["description"], "Fill PDF forms and extract text.");
        assert_eq!(fields["license"], "MIT");
    }

    #[test]
    fn frontmatter_requires_a_closed_block() {
        assert!(frontmatter("---\nname: x\n").is_empty());
        assert!(frontmatter("name: x\n---\n").is_empty());
    }
}
