//! The credential-word signal for a call that names only tracked documents.
//!
//! `perl -pi -e 's/v1/v2/' contributions/command.kubernetes-secrets.json` and
//! a structured Read of the same file raise the signal through the word in
//! the file name alone. When every path value and every command word that
//! carries such a word resolves to a document proven by
//! `tracked_credential_names`, the signal is cleared; the rest of the command
//! text must then hold no credential word of its own.

use super::GenericSignals;
use crate::pretool::search_scope_tracked::names::tracked_document;
use crate::pretool::secret_aliases::{decision_names_secret_alias, operand};
use crate::pretool::{sensitive_command, sensitive_command_input, PathContext, PreToolDecisionV1};
use std::path::Path;

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
        let proven = |value: &str| {
            let supplied = Path::new(value);
            let target = match cwd {
                _ if supplied.is_absolute() => supplied.to_path_buf(),
                Some(cwd) => Path::new(cwd).join(supplied),
                None => return false,
            };
            std::fs::canonicalize(target).is_ok_and(|canonical| tracked_document(&canonical, cwd))
        };
        let paths_proven = self
            .path_values
            .iter()
            .filter(|value| sensitive_command(value))
            .all(|value| proven(value.as_str()));
        let Some(command) = self.command.as_deref() else {
            return paths_proven;
        };
        let Some(Ok(decision)) = decision else {
            return false;
        };
        let mut rest = command.to_owned();
        let words = decision
            .command_model
            .segments
            .iter()
            .flat_map(|segment| segment.executable.iter().chain(&segment.arguments));
        for word in words.filter(|word| sensitive_command(word)) {
            match operand(word) {
                Some(value) if proven(value) => rest = rest.replace(value, " "),
                _ => return false,
            }
        }
        // Redirect targets, assignments and any text the model did not split
        // into words stay in `rest` and keep the signal.
        paths_proven && !sensitive_command_input(&rest)
    }
}
