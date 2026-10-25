//! Deterministic secret detection over the bytes a workspace snapshot hashed.
//!
//! The detector is the shared `guard-scanner` engine; this module only decides
//! which snapshot files it may read and reduces each finding to a value that
//! is safe to store. A reported finding carries the rule id, severity, the
//! root-relative path, the line, and a keyed fingerprint. The matched text is
//! dropped here, at the boundary, and is never serialized, logged or kept in a
//! returned structure.
//!
//! Files Guard treats as credential stores (`.env*`, key and certificate
//! files, and every path the secret-path probe recognizes) are not read for
//! this scan. They are counted as skips so coverage reports what was left out;
//! a skip is never a finding.

use guard_command::secret_path_probe::is_secret_path;
use guard_scanner::repository_scanner::decode_text;
use guard_scanner::secret_detection::{detector_version, scan_secret_text, SecretFinding};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-secrets.v1";
pub(super) const MAX_SECRET_FINDINGS: usize = 500;
/// Hex characters kept from the keyed digest: 128 bits dedupes a secret across
/// runs without storing the full digest.
const FINGERPRINT_HEX_CHARS: usize = 32;
const SOURCE: &str = "working_tree";

/// Key, certificate and keystore files. The secret-path probe only knows
/// credential-store names, so file types that hold key material by format are
/// listed here.
const KEY_MATERIAL_EXTENSIONS: [&str; 13] = [
    "pem", "key", "p8", "p12", "pfx", "crt", "cer", "der", "jks", "keystore", "gpg", "asc", "ppk",
];

pub(super) struct SecretScan {
    pub(super) fingerprint_key: [u8; 32],
    findings: Vec<Value>,
    files_scanned: usize,
    bytes_scanned: u64,
    skipped_credential_store: usize,
    skipped_not_text: usize,
    finding_cap_hit: bool,
}

/// Counts the walk already holds that describe files this scan never read.
pub(super) struct WalkSkips {
    pub(super) sensitive: usize,
    pub(super) oversize: usize,
}

impl SecretScan {
    /// `codebase_key` scopes the fingerprint to a repository, so one secret
    /// dedupes across worktrees and runs without matching another
    /// repository's fingerprints.
    pub(super) fn new(codebase_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"guard.workspace-secret-fingerprint.v1\0");
        hasher.update(codebase_key.as_bytes());
        Self {
            fingerprint_key: hasher.finalize().into(),
            findings: Vec::new(),
            files_scanned: 0,
            bytes_scanned: 0,
            skipped_credential_store: 0,
            skipped_not_text: 0,
            finding_cap_hit: false,
        }
    }

    /// Whether the content of `relative` may be read for this scan. A
    /// credential store is counted as a skip and answers `false`.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if is_credential_store(relative) {
            self.skipped_credential_store += 1;
            return false;
        }
        true
    }

    /// Scan the exact bytes that were hashed for `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        let Some(text) = decode_text(relative, content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        self.bytes_scanned += content.len() as u64;
        let remaining = MAX_SECRET_FINDINGS.saturating_sub(self.findings.len());
        if remaining == 0 {
            self.finding_cap_hit = true;
            return;
        }
        let summary = scan_secret_text(text, relative, SOURCE, None, remaining);
        if summary.findings.len() >= remaining {
            self.finding_cap_hit = true;
        }
        for finding in summary.findings {
            if let Some(redacted) = self.redact(finding) {
                self.findings.push(redacted);
            }
        }
    }

    fn redact(&self, mut finding: SecretFinding) -> Option<Value> {
        let fingerprint = finding.fingerprint(&self.fingerprint_key).ok()?;
        finding.candidate.zeroize();
        Some(json!({
            "rule_id": finding.rule_id,
            "family": finding.family,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "line": finding.line,
            "path": finding.path,
            "fingerprint": &fingerprint[..FINGERPRINT_HEX_CHARS],
        }))
    }

    /// `incomplete_reasons` names the snapshot limits that left files unread;
    /// the scan is incomplete under any of them or when it hit its own cap.
    pub(super) fn report(&self, skips: &WalkSkips, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        if self.finding_cap_hit {
            truncation.push("max_findings");
        }
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": detector_version(),
            "status": if truncation.is_empty() { "complete" } else { "incomplete" },
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "skipped": {
                "credential_store": skips.sensitive + self.skipped_credential_store,
                "not_text": self.skipped_not_text,
                "oversize": skips.oversize,
            },
            "truncation_reasons": truncation,
            "findings": self.findings,
        })
    }
}

fn is_credential_store(relative: &str) -> bool {
    let basename = relative.rsplit('/').next().unwrap_or(relative);
    if let Some((_, extension)) = basename.rsplit_once('.') {
        if KEY_MATERIAL_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
        {
            return true;
        }
    }
    is_secret_path(relative, None, None)
}
