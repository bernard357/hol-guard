//! Codex tool-output command scopes and the caller facts the resident's
//! inspection host reads.
//!
//! `CodexToolOutputFactsV1` carries the observed caller state (process working
//! directory, home, account home, groups, a bounded environment snapshot and
//! the `git` executable) that every resident command review answers git and
//! environment questions from.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One command reviewed with a working directory and an optional home.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandScopeV1 {
    pub command: String,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
}

/// Several commands from one post-tool payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandsScopeV1 {
    pub commands: Vec<String>,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
}

/// One command reviewed for secret-like source names.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexSecretNameScopeV1 {
    pub command: String,
    pub cwd: Option<String>,
    pub home_dir: Option<String>,
    /// Apply the shell execution-context policy (tool-output variant).
    pub exec_context: bool,
}

/// One command with a working directory only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandCwdV1 {
    pub command: String,
    pub cwd: Option<String>,
}

/// One command text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexCommandTextV1 {
    pub command: String,
}

/// One post-tool hook payload projection: the commands, tool input and
/// collected response text the credential-output review reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexPostToolOutputV1 {
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodexToolOutputActionV1 {
    /// A read-only source search, view, chain or pipeline.
    ReadOnlyInspection(CodexCommandScopeV1),
    /// Every post-tool command is a read-only inspection or git metadata read.
    PostToolReadOnly(CodexCommandsScopeV1),
    /// The same verdict over the commands the payload names: a packed body
    /// carrying exactly `tool_name`, `tool_input`, `cwd` and `home_dir`.
    PostToolReadOnlyPayload(CodexPostToolOutputV1),
    /// A command targets a secret-like source file name.
    SecretLikeSourceName(CodexSecretNameScopeV1),
    /// The `git diff` pathspec selection identity (`value`).
    GitPathspecIdentity(CodexCommandCwdV1),
    /// The context-free tail of the local-content-read review.
    LocalContentTail(CodexCommandCwdV1),
    /// An environment dump piped onward.
    ReadsEnvironmentPipeline(CodexCommandTextV1),
    /// A focused pytest verification command.
    FocusedPytest(CodexCommandTextV1),
    /// A read-only git metadata command.
    GitMetadata(CodexCommandCwdV1),
    /// The credential-looking post-tool output artifact (`value`).
    PostToolOutput(CodexPostToolOutputV1),
}

/// Observed caller facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodexToolOutputFactsV1 {
    /// `os.getcwd()` of the caller.
    pub process_cwd: String,
    /// `Path.home()` of the caller.
    pub home: String,
    /// The passwd-database home of the current account, when resolvable.
    pub account_home: Option<String>,
    /// Observed process group ids (primary and supplementary).
    pub groups: Vec<u32>,
    /// Bounded snapshot of the process environment the review reads.
    pub environment: BTreeMap<String, String>,
    /// `shutil.which("git")` of the caller.
    pub git_executable: Option<String>,
}
