//! `hol-guard plugin links`: the install commands users paste into each
//! runtime, and where to list the plugin.

use serde::Serialize;

use crate::detect::Detection;
use crate::emit::{self, Runtime};
use crate::model::{Plugin, SourceKind};

#[derive(Debug, Serialize)]
pub struct Install {
    pub runtime: Runtime,
    pub commands: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Step {
    pub id: &'static str,
    pub done: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct Links {
    pub repository: Option<String>,
    pub install: Vec<Install>,
    pub hol: Option<HolLinks>,
    pub checklist: Vec<Step>,
}

#[derive(Debug, Serialize)]
pub struct HolLinks {
    /// Connects the repository to its HOL listing and verifies ownership.
    pub connect: String,
    pub submit: String,
}

pub fn links(detection: &Detection) -> Links {
    let plugin = &detection.plugin;
    let repository = plugin.github_repository();
    let has = |kind: SourceKind| detection.sources.iter().any(|source| source.kind == kind);
    let mut install = Vec::new();
    if let Some(repository) = &repository {
        let marketplace = plugin
            .marketplace
            .as_ref()
            .and_then(|marketplace| marketplace.name.clone());
        let listed = plugin.name.as_ref().filter(|name| {
            plugin
                .marketplace
                .as_ref()
                .is_some_and(|marketplace| marketplace.plugins.contains(name))
        });
        if let (Some(marketplace), Some(name)) = (&marketplace, listed) {
            if has(SourceKind::ClaudeMarketplace) {
                install.push(Install {
                    runtime: Runtime::ClaudeCode,
                    commands: vec![
                        format!("/plugin marketplace add {repository}"),
                        format!("/plugin install {name}@{marketplace}"),
                    ],
                    verify: Some("claude plugin list".to_owned()),
                });
            }
            if has(SourceKind::CodexMarketplace) {
                install.push(Install {
                    runtime: Runtime::Codex,
                    commands: vec![
                        format!("codex plugin marketplace add {repository}"),
                        format!("codex plugin add {name}@{marketplace}"),
                    ],
                    verify: None,
                });
            }
        }
        if detection.sources.iter().any(|source| {
            source.kind == SourceKind::GeminiExtension && source.path == "gemini-extension.json"
        }) {
            install.push(Install {
                runtime: Runtime::GeminiCli,
                commands: vec![format!(
                    "gemini extensions install https://github.com/{repository}"
                )],
                verify: Some("gemini extensions list".to_owned()),
            });
        }
        if plugin
            .skills
            .iter()
            .any(|skill| emit::skill_slug(skill).is_some())
        {
            install.push(Install {
                runtime: Runtime::AgentSkills,
                commands: vec![format!("npx skills add {repository}")],
                verify: Some("npx skills list".to_owned()),
            });
        }
    }
    Links {
        hol: repository.as_ref().map(|repository| HolLinks {
            connect: format!("https://hol.org/plugins/connect?repo={repository}"),
            submit: "https://hol.org/registry/plugins/submit?intent=launch".to_owned(),
        }),
        checklist: checklist(detection, plugin, repository.is_some()),
        repository,
        install,
    }
}

fn checklist(detection: &Detection, plugin: &Plugin, on_github: bool) -> Vec<Step> {
    let has = |kind: SourceKind| detection.sources.iter().any(|source| source.kind == kind);
    let listed = plugin.name.as_ref().is_some_and(|name| {
        plugin
            .marketplace
            .as_ref()
            .is_some_and(|marketplace| marketplace.plugins.contains(name))
    });
    vec![
        Step {
            id: "github_repository",
            done: on_github,
            message: "Publish the source on GitHub and set repository in the manifest.".to_owned(),
        },
        Step {
            id: "claude_marketplace",
            done: has(SourceKind::ClaudeMarketplace) && listed,
            message: "List the plugin in .claude-plugin/marketplace.json so Claude Code can install it from the repository."
                .to_owned(),
        },
        Step {
            id: "codex_marketplace",
            done: has(SourceKind::CodexMarketplace) && listed,
            message: "List the plugin in .agents/plugins/marketplace.json so Codex can install it from the repository."
                .to_owned(),
        },
        Step {
            id: "mcp_registry",
            done: has(SourceKind::McpServer),
            message: "Publish MCP servers to the MCP Registry with server.json (https://github.com/modelcontextprotocol/registry)."
                .to_owned(),
        },
        Step {
            id: "hol_listing",
            done: false,
            message: "Connect the repository on HOL to verify ownership and claim the listing.".to_owned(),
        },
    ]
}
