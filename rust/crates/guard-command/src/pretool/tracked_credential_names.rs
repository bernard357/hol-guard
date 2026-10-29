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
use crate::pretool::secret_aliases::operand;
use crate::pretool::sensitive_command;
use crate::{CanonicalCommandV1, CommandSegmentV1};
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
    (same_tree || super::super::worktree_writes::same_repository_worktree(&workspace, canonical))
        && committed_document(canonical)
}

/// Whether `path` is a small, secret-free document listed in the index of
/// whichever repository holds it. A recursive search reads every file it
/// reaches, so a sibling checkout's committed catalog entry is held to the
/// same proof as one in the session's own repository.
pub(in crate::pretool) fn committed_document(path: &Path) -> bool {
    guard_secure_fs::source_document_extension(path)
        && !path
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
        && guard_secure_fs::sensitive_path_family(path).is_none()
        && TrackedFiles::default().non_secret(path)
        && std::fs::read(path).is_ok_and(|bytes| !secret_object(&String::from_utf8_lossy(&bytes)))
}

/// Whether `value`, a path as a command or tool spelled it, resolves to a
/// document [`tracked_document`] proves.
pub(in crate::pretool) fn resolves_to_tracked(value: &str, cwd: Option<&str>) -> bool {
    let supplied = Path::new(value);
    let target = match cwd {
        _ if supplied.is_absolute() => supplied.to_path_buf(),
        Some(cwd) => Path::new(cwd).join(supplied),
        None => return false,
    };
    std::fs::canonicalize(target).is_ok_and(|canonical| tracked_document(&canonical, cwd))
}

/// `text` with each credential-named word of `words` left out, or `None` when
/// one of those words is anything but a path to a proven tracked document.
/// Text the words do not cover (redirect targets, assignments, a script's own
/// words) stays in place for the caller's screen.
pub(in crate::pretool) fn without_tracked_words<'a>(
    text: &str,
    words: impl IntoIterator<Item = &'a String>,
    cwd: Option<&str>,
) -> Option<String> {
    let mut rest = text.to_owned();
    for word in words.into_iter().filter(|word| sensitive_command(word)) {
        let value = operand(word).filter(|value| resolves_to_tracked(value, cwd))?;
        rest = rest.replace(value, " ");
    }
    Some(rest)
}

/// The text a credential-word screen reads for `segment`: `text`, or the
/// segment's own text, without the words that name tracked documents when
/// every credential-named word does.
pub(in crate::pretool) fn segment_screen_text(
    segment: &CommandSegmentV1,
    text: Option<String>,
    cwd: Option<&str>,
) -> String {
    let text = text.unwrap_or_else(|| segment.text.clone());
    let words = segment.executable.iter().chain(&segment.arguments);
    without_tracked_words(&text, words, cwd).unwrap_or(text)
}

/// The text the command authority's credential-word screen reads: the
/// command without heredoc data bodies, and without the words that name
/// tracked documents when every credential-named word in it does.
pub(in crate::pretool) fn command_screen_text(
    model: &CanonicalCommandV1,
    text: &str,
    cwd: Option<&str>,
) -> String {
    let text = super::super::data_heredocs::without_data_bodies(text);
    let words = model
        .segments
        .iter()
        .flat_map(|segment| segment.executable.iter().chain(&segment.arguments));
    without_tracked_words(&text, words, cwd).unwrap_or(text)
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
