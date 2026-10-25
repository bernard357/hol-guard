//! Risky launch settings in a configured MCP server.
//!
//! A project's MCP configuration names the program an agent starts for each
//! server, or the URL it connects to. These rules read that configuration
//! only: they never start the server, resolve its program or fetch its URL.
//!
//! A server launched through a shell script runs the same pipeline screen the
//! hook applies to an agent's shell commands, so a script that pipes a
//! download into a shell or sends the environment over the network is named
//! the same way in both places. Windows `cmd /c` and PowerShell scripts are not
//! read here.

use std::net::IpAddr;

use crate::pretool::pipe_attacks::{pipe_attack, ENVIRONMENT_EXFILTRATION, REMOTE_CODE};
use crate::{parse_command, CommandModelRequestV1};

#[cfg(test)]
#[path = "mcp_config_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpConfigRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const REMOTE_CODE_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.remote-code",
    category: "execution",
    severity: "critical",
    confidence: "strong",
    title: "MCP server launch runs downloaded code",
    reason: "The server starts through a shell script that pipes a download into a shell or interpreter, so it runs remote code without review.",
    false_positive_hint: None,
};

pub const ENVIRONMENT_EXFILTRATION_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.environment-exfiltration",
    category: "exfiltration",
    severity: "critical",
    confidence: "strong",
    title: "MCP server launch sends environment variables",
    reason: "The server starts through a shell script that pipes the process environment, which often holds secrets, to a network sender.",
    false_positive_hint: None,
};

pub const PRIVILEGED_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.privileged-launch",
    category: "privilege",
    severity: "high",
    confidence: "strong",
    title: "MCP server launches with elevated privileges",
    reason: "The server starts through sudo or a similar wrapper, so every tool it exposes runs with administrator rights.",
    false_positive_hint: Some("Expected only for a server that manages the machine itself."),
};

pub const PLAIN_HTTP_REMOTE: McpConfigRule = McpConfigRule {
    id: "mcp.config.remote-plain-http",
    category: "transport",
    severity: "high",
    confidence: "strong",
    title: "Remote MCP server uses plain HTTP",
    reason: "The server URL uses http to a host that is not loopback, so tool calls and replies cross the network unencrypted and can be read or changed.",
    false_positive_hint: None,
};

const SHELLS: &[&str] = &["ash", "bash", "dash", "fish", "ksh", "mksh", "sh", "zsh"];
const PRIVILEGE_WRAPPERS: &[&str] = &["doas", "gsudo", "pkexec", "run0", "sudo"];
const PRIVILEGE_VALUE_OPTIONS: &[&str] = &[
    "-C", "-D", "-U", "-g", "-h", "-p", "-r", "-t", "-u", "--chdir", "--group", "--user",
];
const ENV_VALUE_OPTIONS: &[&str] = &["-C", "-S", "-u", "--chdir", "--split-string", "--unset"];
const SHELL_VALUE_OPTIONS: &[&str] = &["+O", "+o", "-O", "-o", "--init-file", "--rcfile"];

/// The rules a server's launch `command` and `args`, or its `url`, match, in
/// rule order and each at most once.
pub fn detect_mcp_config_risk(
    command: Option<&str>,
    args: &[String],
    url: Option<&str>,
) -> Vec<McpConfigRule> {
    let mut found = Vec::new();
    if let Some(command) = command.filter(|command| !command.trim().is_empty()) {
        let argv: Vec<&str> = std::iter::once(command)
            .chain(args.iter().map(String::as_str))
            .collect();
        let launch = after_env(&argv);
        let (mut privileged, launch) = after_privilege(launch);
        if let Some(script) = shell_script(after_env(launch)) {
            if let Ok(model) = parse_command(&shell_request(script)) {
                match pipe_attack(&model) {
                    Some(attack) if attack == REMOTE_CODE => found.push(REMOTE_CODE_LAUNCH),
                    Some(attack) if attack == ENVIRONMENT_EXFILTRATION => {
                        found.push(ENVIRONMENT_EXFILTRATION_LAUNCH)
                    }
                    _ => {}
                }
                privileged |= model.segments.iter().any(|segment| {
                    segment
                        .executable
                        .as_deref()
                        .is_some_and(is_privilege_wrapper)
                        || segment
                            .wrapper_chain
                            .iter()
                            .any(|wrapper| is_privilege_wrapper(wrapper))
                });
            }
        }
        if privileged {
            found.push(PRIVILEGED_LAUNCH);
        }
    }
    if url.is_some_and(is_plain_http_remote) {
        found.push(PLAIN_HTTP_REMOTE);
    }
    found
}

fn shell_request(script: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: script.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

/// The program name without its directory or a Windows `.exe` suffix.
fn program(word: &str) -> &str {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    match name.len().checked_sub(4) {
        Some(stem) if name.is_char_boundary(stem) && name[stem..].eq_ignore_ascii_case(".exe") => {
            &name[..stem]
        }
        _ => name,
    }
}

fn is_privilege_wrapper(word: &str) -> bool {
    PRIVILEGE_WRAPPERS.contains(&program(word))
}

/// The words after a leading `env` and its options and assignments.
fn after_env<'a>(argv: &'a [&'a str]) -> &'a [&'a str] {
    if argv.first().map(|word| program(word)) != Some("env") {
        return argv;
    }
    skip_options(&argv[1..], ENV_VALUE_OPTIONS, true)
}

/// Whether the launch goes through a privilege wrapper, and what it runs.
fn after_privilege<'a>(argv: &'a [&'a str]) -> (bool, &'a [&'a str]) {
    match argv.first() {
        Some(word) if is_privilege_wrapper(word) => (
            true,
            skip_options(&argv[1..], PRIVILEGE_VALUE_OPTIONS, false),
        ),
        _ => (false, argv),
    }
}

fn skip_options<'a>(
    words: &'a [&'a str],
    value_options: &[&str],
    assignments: bool,
) -> &'a [&'a str] {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if *word == "--" {
            index += 1;
            break;
        }
        if value_options.contains(word) {
            index += 2;
        } else if word.starts_with('-') || (assignments && is_assignment(word)) {
            index += 1;
        } else {
            break;
        }
    }
    words.get(index..).unwrap_or_default()
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The script a shell launch runs with `-c` (or fish's `--command`).
fn shell_script<'a>(argv: &'a [&'a str]) -> Option<&'a str> {
    if !SHELLS.contains(&program(argv.first()?)) {
        return None;
    }
    let mut runs_script = false;
    let mut words = argv[1..].iter();
    while let Some(word) = words.next() {
        if *word == "--command" {
            return words.next().copied();
        }
        if let Some(script) = word.strip_prefix("--command=") {
            return Some(script);
        }
        if *word == "--" {
            break;
        }
        if SHELL_VALUE_OPTIONS.contains(word) {
            words.next();
        } else if word.starts_with("--") {
            continue;
        } else if let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) {
            runs_script |= cluster.contains('c');
        } else if word.starts_with('+') && word.len() > 1 {
            continue;
        } else {
            return runs_script.then_some(*word);
        }
    }
    if runs_script {
        words.next().copied()
    } else {
        None
    }
}

/// An `http` URL whose host is not loopback.
fn is_plain_http_remote(url: &str) -> bool {
    let url = url.trim();
    let Some(rest) = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .and_then(|_| url.get(7..))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => host_port.split(':').next().unwrap_or_default(),
    };
    !host.is_empty() && !is_loopback_host(host)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Err(_) => false,
    }
}
