//! `mcp-config-assess --stdin`: check the MCP servers a worktree configures
//! for risky launch settings.
//!
//! The caller sends each server's launch command, arguments and URL with the
//! root-relative path of the file that configures it. The rules are the shared
//! [`guard_command::mcp_config_risk`] set. Each finding carries the rule's
//! fixed wording, the path and the server name, never the command or URL, so
//! nothing from the configuration is stored beyond where it lives.
//!
//! The command reads no files and starts no processes.

use std::collections::{BTreeMap, BTreeSet};

use guard_command::mcp_config_risk::detect_mcp_config_risk;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const COMMAND: &str = "mcp-config-assess";
pub(crate) const FEATURE: &str = "mcp-config-assess-v1";
const REQUEST_SCHEMA: &str = "guard.workspace-mcp-config-request.v1";
const RESULT_SCHEMA: &str = "guard.workspace-mcp-config.v1";
const FINDING_ID_DOMAIN: &str = "guard.workspace-mcp-config.v1";

const MAX_SERVERS: usize = 512;
const MAX_ARGS: usize = 256;
const MAX_TEXT: usize = 8_192;
const MAX_FINDINGS: usize = 200;

#[cfg(test)]
#[path = "workspace_mcp_config_tests.rs"]
mod tests;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    servers: Vec<ServerInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerInput {
    path: String,
    server: String,
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    url: Option<String>,
}

impl ServerInput {
    fn within_bounds(&self) -> bool {
        self.args.len() <= MAX_ARGS
            && [&self.path, &self.server]
                .into_iter()
                .chain(&self.command)
                .chain(&self.args)
                .chain(&self.url)
                .all(|text| text.len() <= MAX_TEXT)
    }
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| "mcp_config_request_invalid".to_owned())?;
    Ok(match assess(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

fn assess(request: &Request) -> Result<Value, String> {
    if request.schema != REQUEST_SCHEMA {
        return Err("mcp_config_request_schema".to_owned());
    }
    let mut truncation = BTreeSet::new();
    if request.servers.len() > MAX_SERVERS {
        truncation.insert("max_servers");
    }
    let mut findings = BTreeMap::new();
    let (mut scanned, mut oversize) = (0_usize, 0_usize);
    for server in request.servers.iter().take(MAX_SERVERS) {
        if !server.within_bounds() {
            oversize += 1;
            truncation.insert("server_oversize");
            continue;
        }
        scanned += 1;
        let rules = detect_mcp_config_risk(
            server.command.as_deref(),
            &server.args,
            server.url.as_deref(),
        );
        for rule in rules {
            let finding_id = finding_id(rule.id, &server.path, &server.server);
            if !findings.contains_key(&finding_id) && findings.len() >= MAX_FINDINGS {
                truncation.insert("max_findings");
                break;
            }
            findings.insert(
                finding_id.clone(),
                json!({
                    "finding_id": finding_id,
                    "rule_id": rule.id,
                    "category": rule.category,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "title": rule.title,
                    "reason": rule.reason,
                    "false_positive_hint": rule.false_positive_hint,
                    "path": server.path,
                    "server": server.server,
                }),
            );
        }
    }
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "status": if truncation.is_empty() { "complete" } else { "incomplete" },
        "servers_scanned": scanned,
        "skipped": {"oversize": oversize},
        "truncation_reasons": truncation.into_iter().collect::<Vec<_>>(),
        "findings": findings.into_values().collect::<Vec<_>>(),
    }))
}

fn finding_id(rule_id: &str, path: &str, server: &str) -> String {
    let mut digest = Sha256::new();
    for part in [FINDING_ID_DOMAIN, rule_id, path, server] {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())[..32].to_owned()
}
