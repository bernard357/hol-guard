//! `workspace-snapshot --stdin`: the bounded content snapshot that binds a
//! background workspace assessment to the exact files it read.
//!
//! The walk never follows a symlink, never executes Git and never reads a
//! sensitive basename. Every admitted regular file contributes its relative
//! path, size and SHA-256 to a sorted manifest; directories skipped by policy,
//! symlinks, oversize files and unreadable entries contribute an exclusion
//! record instead, so a change to what was left out still changes the digest.
//! A file whose identity changed while it was read is reported as unstable and
//! the snapshot is partial: callers must not treat it as a consistent view.
//!
//! `stat` mode reads no file content. It digests path, size, mtime and inode
//! only and exists to notice that something changed between content
//! snapshots; it is never an assessment identity.

use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::is_audit_sensitive_basename;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::workspace_snapshot_file::{hash_stable, inode, mtime_ns, HashError};
use crate::workspace_snapshot_git::{git_identity, GitIdentity};

pub(crate) const COMMAND: &str = "workspace-snapshot";
pub(crate) const FEATURE: &str = "workspace-snapshot-v1";
const RESULT_SCHEMA: &str = "guard.workspace-snapshot.v1";
const CONTRACT_VERSION: u32 = 1;

pub(crate) const DEFAULT_MAX_ENTRIES: usize = 10_000;
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const HARD_MAX_ENTRIES: usize = 100_000;
const HARD_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Exclusion records past this count are folded into one overflow record so
/// a tree full of skipped directories cannot grow the reply without bound.
const MAX_EXCLUSION_RECORDS: usize = 20_000;

/// Vendored, generated and dependency directories. Their content is owned by
/// a lockfile or a build, not by the developer's edits.
pub(crate) const SKIP_DIRS: [&str; 22] = [
    ".git",
    ".hg",
    ".svn",
    ".jj",
    "node_modules",
    "bower_components",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".turbo",
    "target",
    ".guard",
    ".worktrees",
    "worktrees",
];

/// Basenames whose content detectors read for dependency risk. An oversize
/// file in this set leaves the snapshot partial instead of merely excluded.
const DETECTOR_INPUT_BASENAMES: [&str; 25] = [
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
];

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotMode {
    Content,
    Stat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotRequest {
    pub(crate) root: String,
    pub(crate) mode: SnapshotMode,
    #[serde(default)]
    pub(crate) max_entries: usize,
    #[serde(default)]
    pub(crate) max_total_bytes: u64,
    #[serde(default)]
    pub(crate) max_file_bytes: u64,
}

struct Limits {
    entries: usize,
    total_bytes: u64,
    file_bytes: u64,
}

impl Limits {
    fn from_request(request: &SnapshotRequest) -> Self {
        fn bounded<T: Ord + Copy + Default>(value: T, default: T, hard: T) -> T {
            if value == T::default() {
                default
            } else {
                value.min(hard)
            }
        }
        Self {
            entries: bounded(request.max_entries, DEFAULT_MAX_ENTRIES, HARD_MAX_ENTRIES),
            total_bytes: bounded(
                request.max_total_bytes,
                DEFAULT_MAX_TOTAL_BYTES,
                HARD_MAX_TOTAL_BYTES,
            ),
            file_bytes: bounded(
                request.max_file_bytes,
                DEFAULT_MAX_FILE_BYTES,
                HARD_MAX_FILE_BYTES,
            ),
        }
    }

    fn policy_line(&self) -> String {
        format!(
            "policy\0v{CONTRACT_VERSION}\0{}\0{}\0{}\0{}",
            self.entries,
            self.total_bytes,
            self.file_bytes,
            SKIP_DIRS.join(",")
        )
    }
}

#[derive(Default)]
struct Walk {
    /// `path\0size\0sha256` (content) or `path\0size\0mtime\0ino` (stat).
    entries: Vec<String>,
    exclusions: Vec<String>,
    exclusion_overflow: usize,
    hashed_bytes: u64,
    counts: ExclusionCounts,
    unreadable: usize,
    unstable: usize,
    entry_cap_hit: bool,
    byte_cap_hit: bool,
    oversize_detector_input: bool,
}

#[derive(Default)]
struct ExclusionCounts {
    directories: usize,
    sensitive: usize,
    oversize: usize,
    symlinks: usize,
    special: usize,
}

impl Walk {
    fn exclude(&mut self, record: String) {
        if self.exclusions.len() < MAX_EXCLUSION_RECORDS {
            self.exclusions.push(record);
        } else {
            self.exclusion_overflow += 1;
        }
    }
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: SnapshotRequest = serde_json::from_slice(bytes)
        .map_err(|_| "workspace_snapshot_request_invalid".to_owned())?;
    Ok(match snapshot(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

pub(crate) fn snapshot(request: &SnapshotRequest) -> Result<Value, String> {
    let requested = PathBuf::from(&request.root);
    if !requested.is_absolute() {
        return Err("workspace_snapshot_root_not_absolute".to_owned());
    }
    let root = fs::canonicalize(&requested).map_err(|_| "workspace_snapshot_root_missing")?;
    if !fs::metadata(&root).is_ok_and(|meta| meta.is_dir()) {
        return Err("workspace_snapshot_root_not_directory".to_owned());
    }
    let root_text = root
        .to_str()
        .ok_or("workspace_snapshot_root_not_utf8")?
        .to_owned();
    let limits = Limits::from_request(request);
    let git = git_identity(&root);
    let mut walk = Walk::default();
    walk_directory(&root, "", request.mode, &limits, &mut walk);
    walk.entries.sort();
    walk.exclusions.sort();

    let worktree_key = keyed_digest("worktree", &root_text);
    let codebase_key = keyed_digest(
        "codebase",
        git.common_dir.as_deref().unwrap_or(root_text.as_str()),
    );
    let input_manifest_digest = input_manifest_digest(&limits, &walk);
    let snapshot_digest = snapshot_digest(
        request.mode,
        &worktree_key,
        &codebase_key,
        &git,
        &input_manifest_digest,
        &walk,
    );
    let mut partial_reasons: Vec<&str> = Vec::new();
    if walk.entry_cap_hit {
        partial_reasons.push("entry_cap");
    }
    if walk.byte_cap_hit {
        partial_reasons.push("byte_cap");
    }
    if walk.oversize_detector_input {
        partial_reasons.push("oversize_detector_input");
    }
    if walk.unreadable > 0 {
        partial_reasons.push("unreadable");
    }
    if walk.unstable > 0 {
        partial_reasons.push("unstable");
    }
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "mode": match request.mode {
            SnapshotMode::Content => "content",
            SnapshotMode::Stat => "stat",
        },
        "root": root_text,
        "worktree_key": worktree_key,
        "codebase_key": codebase_key,
        "git": {
            "head_commit": git.head_commit,
            "head_ref": git.head_ref,
            "linked_worktree": git.linked_worktree,
        },
        "snapshot_digest": snapshot_digest,
        "input_manifest_digest": input_manifest_digest,
        "entry_count": walk.entries.len(),
        "hashed_bytes": walk.hashed_bytes,
        "excluded": {
            "directories": walk.counts.directories,
            "sensitive": walk.counts.sensitive,
            "oversize": walk.counts.oversize,
            "symlinks": walk.counts.symlinks,
            "special": walk.counts.special,
        },
        "unreadable_count": walk.unreadable,
        "unstable_count": walk.unstable,
        "coverage": if partial_reasons.is_empty() { "complete" } else { "partial" },
        "partial_reasons": partial_reasons,
        "limits": {
            "max_entries": limits.entries,
            "max_total_bytes": limits.total_bytes,
            "max_file_bytes": limits.file_bytes,
        },
    }))
}

fn keyed_digest(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("guard.workspace-snapshot.{domain}.v1\0").as_bytes());
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn input_manifest_digest(limits: &Limits, walk: &Walk) -> String {
    let mut hasher = Sha256::new();
    hasher.update(limits.policy_line().as_bytes());
    for record in &walk.exclusions {
        hasher.update(b"\nexclude\0");
        hasher.update(record.as_bytes());
    }
    hasher.update(format!("\noverflow\0{}", walk.exclusion_overflow).as_bytes());
    hex::encode(hasher.finalize())
}

fn snapshot_digest(
    mode: SnapshotMode,
    worktree_key: &str,
    codebase_key: &str,
    git: &GitIdentity,
    input_manifest_digest: &str,
    walk: &Walk,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "{RESULT_SCHEMA}\0{CONTRACT_VERSION}\0{mode:?}\0{worktree_key}\0{codebase_key}\0{}\0{}\0{input_manifest_digest}",
            git.head_commit.as_deref().unwrap_or("-"),
            git.head_ref.as_deref().unwrap_or("-"),
        )
        .as_bytes(),
    );
    for entry in &walk.entries {
        hasher.update(b"\nentry\0");
        hasher.update(entry.as_bytes());
    }
    hasher.update(
        format!(
            "\nstate\0{}\0{}\0{}\0{}\0{}",
            walk.unreadable,
            walk.unstable,
            walk.entry_cap_hit,
            walk.byte_cap_hit,
            walk.oversize_detector_input
        )
        .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

fn join(relative: &str, name: &str) -> String {
    if relative.is_empty() {
        name.to_owned()
    } else {
        format!("{relative}/{name}")
    }
}

fn walk_directory(
    directory: &Path,
    relative: &str,
    mode: SnapshotMode,
    limits: &Limits,
    walk: &mut Walk,
) {
    let Ok(reader) = fs::read_dir(directory) else {
        walk.unreadable += 1;
        walk.exclude(format!("{relative}\0unreadable_directory"));
        return;
    };
    let mut names: Vec<(String, std::ffi::OsString)> = Vec::new();
    for entry in reader {
        let Ok(entry) = entry else {
            walk.unreadable += 1;
            continue;
        };
        let os_name = entry.file_name();
        match os_name.to_str() {
            Some(name) => names.push((name.to_owned(), os_name.clone())),
            None => {
                walk.unreadable += 1;
                walk.exclude(format!("{relative}\0non_utf8_name"));
            }
        }
    }
    // Readdir order is filesystem specific; the walk visits names in order so
    // the entry cap always keeps the same prefix.
    names.sort();
    for (name, os_name) in names {
        if walk.entry_cap_hit {
            return;
        }
        let path = directory.join(&os_name);
        let child = join(relative, &name);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            walk.unreadable += 1;
            walk.exclude(format!("{child}\0unreadable"));
            continue;
        };
        let kind = metadata.file_type();
        if kind.is_symlink() {
            walk.counts.symlinks += 1;
            let target = fs::read_link(&path)
                .map(|target| hex::encode(Sha256::digest(target.as_os_str().as_encoded_bytes())))
                .unwrap_or_else(|_| "-".to_owned());
            walk.exclude(format!("{child}\0symlink\0{target}"));
        } else if kind.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                walk.counts.directories += 1;
                walk.exclude(format!("{child}\0policy_directory"));
            } else {
                walk_directory(&path, &child, mode, limits, walk);
            }
        } else if !kind.is_file() {
            walk.counts.special += 1;
            walk.exclude(format!("{child}\0special"));
        } else if is_audit_sensitive_basename(&name) {
            walk.counts.sensitive += 1;
            walk.exclude(format!("{child}\0sensitive"));
        } else {
            admit_file(&path, &child, &name, &metadata, mode, limits, walk);
        }
    }
}

fn admit_file(
    path: &Path,
    child: &str,
    name: &str,
    metadata: &Metadata,
    mode: SnapshotMode,
    limits: &Limits,
    walk: &mut Walk,
) {
    if walk.entries.len() >= limits.entries {
        walk.entry_cap_hit = true;
        return;
    }
    let size = metadata.len();
    if size > limits.file_bytes {
        walk.counts.oversize += 1;
        if DETECTOR_INPUT_BASENAMES.contains(&name) {
            walk.oversize_detector_input = true;
        }
        walk.exclude(format!("{child}\0oversize\0{size}"));
        return;
    }
    if mode == SnapshotMode::Stat {
        walk.entries.push(format!(
            "{child}\0{size}\0{}\0{}",
            mtime_ns(metadata),
            inode(metadata)
        ));
        return;
    }
    if walk.hashed_bytes.saturating_add(size) > limits.total_bytes {
        walk.byte_cap_hit = true;
        walk.exclude(format!("{child}\0byte_budget\0{size}"));
        return;
    }
    match hash_stable(path, metadata, limits.file_bytes) {
        Ok((digest, read)) => {
            walk.hashed_bytes += read;
            walk.entries.push(format!("{child}\0{read}\0{digest}"));
        }
        Err(HashError::Unstable) => {
            walk.unstable += 1;
            walk.exclude(format!("{child}\0unstable"));
        }
        Err(HashError::Unreadable) => {
            walk.unreadable += 1;
            walk.exclude(format!("{child}\0unreadable"));
        }
    }
}

#[cfg(test)]
#[path = "workspace_snapshot_tests.rs"]
mod tests;
