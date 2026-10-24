//! The runtime-neutral view of one plugin source repository.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    ClaudePlugin,
    CodexPlugin,
    GeminiExtension,
    McpServer,
    ClaudeMarketplace,
    CodexMarketplace,
    McpConfig,
    AgentSkill,
}

impl SourceKind {
    /// Kinds that name a plugin root and carry its metadata.
    pub(crate) fn is_plugin_root(self) -> bool {
        matches!(
            self,
            Self::ClaudePlugin | Self::CodexPlugin | Self::GeminiExtension | Self::McpServer
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    pub kind: SourceKind,
    /// The manifest path, relative to the repository root.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skill {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The directory holding `SKILL.md`, relative to the repository root.
    pub dir: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct McpServer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Environment variable names only; values are never carried.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Marketplace {
    pub name: Option<String>,
    pub path: String,
    pub plugins: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Plugin {
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
    pub keywords: Vec<String>,
    /// The plugin root, relative to the repository root ("" for the root).
    pub base: String,
    pub skills: Vec<Skill>,
    pub mcp_servers: BTreeMap<String, McpServer>,
    pub commands: Vec<String>,
    pub agents: Vec<String>,
    pub hooks: Option<String>,
    pub context_file: Option<String>,
    pub marketplace: Option<Marketplace>,
    #[serde(skip)]
    pub registry_server: Option<Value>,
}

impl Plugin {
    /// `owner/name` when the repository is on GitHub.
    pub fn github_repository(&self) -> Option<String> {
        self.repository.as_deref().and_then(github_full_name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub level: Level,
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    pub(crate) fn error(code: &'static str, path: &str, message: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            code,
            path: path.to_owned(),
            message: message.into(),
        }
    }

    pub(crate) fn warning(code: &'static str, path: &str, message: impl Into<String>) -> Self {
        Self {
            level: Level::Warning,
            code,
            path: path.to_owned(),
            message: message.into(),
        }
    }
}

/// `owner/name` from a GitHub URL, `git@github.com:` remote or `owner/name`.
pub fn github_full_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let unprefixed = trimmed.strip_prefix("git+").unwrap_or(trimmed);
    let rest = [
        "https://github.com/",
        "http://github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
        "github:",
    ]
    .iter()
    .find_map(|prefix| unprefixed.strip_prefix(prefix))
    .unwrap_or(unprefixed);
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut parts = rest.split('/');
    let owner = parts.next()?;
    let name = parts.next()?;
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !valid(owner) || !valid(name) {
        return None;
    }
    // Anything after `owner/name` is a path inside the repository (a tree or
    // blob URL); the repository itself is still `owner/name`.
    if unprefixed.len() != rest.len() || parts.next().is_none() {
        return Some(format!("{owner}/{name}").to_ascii_lowercase());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::github_full_name;

    #[test]
    fn github_full_name_accepts_the_common_spellings() {
        for input in [
            "https://github.com/Acme/Widget",
            "https://github.com/acme/widget.git",
            "git+https://github.com/acme/widget.git",
            "git@github.com:acme/widget.git",
            "https://github.com/acme/widget/tree/main/plugins/x",
            "acme/widget",
        ] {
            assert_eq!(
                github_full_name(input).as_deref(),
                Some("acme/widget"),
                "{input}"
            );
        }
        for input in [
            "https://gitlab.com/acme/widget",
            "widget",
            "acme/widget/extra",
            "",
        ] {
            assert_eq!(github_full_name(input), None, "{input}");
        }
    }
}
