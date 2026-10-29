//! Whether a document whose name carries a credential word is a project file
//! rather than a secret.
//!
//! `command.kubernetes-secrets.json` describes a feature; it holds no secret.
//! The name screens cannot tell that apart from `prod-secrets.json`, so the
//! file itself must prove it: a small regular JSON, YAML, TOML or Markdown file
//! in the session's repository or one of its linked worktrees, listed in that
//! repository's index, outside every credential-store directory, with no
//! credential-shaped value in it and no Kubernetes `Secret` object. Anything
//! else keeps the review its name earns.

use super::TrackedFiles;
use std::path::Path;

/// Whether `canonical`, a resolved path, is a credential-named document that
/// is not proven to be a tracked project file.
pub(in crate::pretool) fn unproven(canonical: &Path, cwd: Option<&str>) -> bool {
    guard_secure_fs::credential_named_path(canonical) && !tracked_document(canonical, cwd)
}

/// Whether `canonical` is a tracked, secret-free document of the session's
/// repository or of a linked worktree of the same repository.
pub(in crate::pretool) fn tracked_document(canonical: &Path, cwd: Option<&str>) -> bool {
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let same_tree =
        repository_root(&workspace).is_some_and(|root| repository_root(canonical) == Some(root));
    guard_secure_fs::source_document_extension(canonical)
        && !canonical
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
        && guard_secure_fs::sensitive_path_family(canonical).is_none()
        && (same_tree
            || super::super::worktree_writes::same_repository_worktree(&workspace, canonical))
        && TrackedFiles::default().non_secret(canonical)
        && std::fs::read(canonical)
            .is_ok_and(|bytes| !secret_object(&String::from_utf8_lossy(&bytes)))
}

/// The nearest directory at or above `path` that holds a `.git` entry.
fn repository_root(path: &Path) -> Option<&Path> {
    path.ancestors()
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
}

/// Whether `text` declares a Kubernetes `Secret`, or any kind named for one
/// (`SealedSecret`, `ExternalSecret`), in YAML, JSON or TOML spelling. A
/// manifest's values are often base64 and pass the secret detector, so the
/// declared kind is the only reliable mark.
fn secret_object(text: &str) -> bool {
    text.match_indices("kind").any(|(at, _)| {
        let rest = text[at + 4..].trim_start_matches(['"', '\'']).trim_start();
        let Some(value) = rest.strip_prefix([':', '=']) else {
            return false;
        };
        let value = value.trim_start().trim_start_matches(['"', '\'']);
        let end = value
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(value.len());
        value[..end].to_ascii_lowercase().contains("secret")
    })
}

#[cfg(test)]
#[path = "tracked_credential_names_tests.rs"]
mod tests;
