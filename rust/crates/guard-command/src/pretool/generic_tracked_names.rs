//! The credential-word signal for a call that names only tracked documents.
//!
//! `perl -pi -e 's/v1/v2/' contributions/command.kubernetes-secrets.json` and
//! a structured Read of the same file raise the signal through the word in
//! the file name alone. When every path value and every command word that
//! carries such a word resolves to a document proven by
//! `tracked_credential_names`, the signal is cleared; the rest of the command
//! text must then hold no credential word of its own.

use super::GenericSignals;
use crate::pretool::search_scope_tracked::names::{
    self, command_words, moves_directory, resolves_to_tracked, without_tracked_words,
};
use crate::pretool::secret_aliases::decision_names_secret_alias;
use crate::pretool::{sensitive_command, sensitive_command_input, PathContext, PreToolDecisionV1};
use serde_json::Value;

impl GenericSignals {
    /// Clears the credential-word signal for a call that names only tracked
    /// documents, then adds any operand that reaches a secret through a link.
    pub(in crate::pretool::generic) fn settle_tracked_names(
        &mut self,
        decision: Option<&Result<PreToolDecisionV1, String>>,
        context: PathContext<'_>,
    ) {
        if self.sensitive_target
            && !self.non_path_sensitive_target
            && !self.declares_secret_object
            && self.names_only_tracked_documents(decision, context.cwd)
        {
            self.sensitive_target = false;
            self.independent_sensitive_target = false;
        }
        // A link to a secret file is that secret under another name.
        self.sensitive_target |= decision_names_secret_alias(decision, context);
    }

    fn names_only_tracked_documents(
        &self,
        decision: Option<&Result<PreToolDecisionV1, String>>,
        cwd: Option<&str>,
    ) -> bool {
        let paths_proven = self
            .path_values
            .iter()
            .filter(|value| sensitive_command(value))
            .all(|value| resolves_to_tracked(value, cwd));
        let Some(command) = self.command.as_deref() else {
            return paths_proven;
        };
        let Some(Ok(decision)) = decision else {
            return false;
        };
        let model = &decision.command_model;
        // Redirect targets, assignments and any text the model did not split
        // into words stay in the rest and keep the signal.
        paths_proven
            && without_tracked_words(command, command_words(model), cwd, moves_directory(model))
                .is_some_and(|rest| !sensitive_command_input(&rest))
    }
}

/// Whether a string anywhere in `payload` declares a Kubernetes `Secret`. An
/// edit that turns a tracked document into a `Secret` manifest keeps the
/// signal, though the file on disk still proves clean.
pub(super) fn declares_secret_object(payload: &Value) -> bool {
    match payload {
        Value::String(text) => names::declares_secret_object(text),
        Value::Array(items) => items.iter().any(declares_secret_object),
        Value::Object(map) => map.values().any(declares_secret_object),
        _ => false,
    }
}
