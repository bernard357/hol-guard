//! Update prompts for installed plugins that publish checked releases on HOL.
//!
//! Guard downloads the public release index (listings whose authors record
//! releases with the HOL Plugin Release workflow) and this module compares
//! each installed plugin's version with it on the device. Nothing about the
//! installed plugins is sent anywhere.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::installed::InstalledPlugin;
use crate::report::{match_listing, IndexEntry};
use crate::MAX_ENTRIES;

/// One release in the public release index.
#[derive(Debug, Clone, Deserialize)]
pub struct IndexedRelease {
    pub version: String,
    #[serde(default, rename = "maxSeverity")]
    pub max_severity: Option<String>,
    #[serde(default, rename = "fixesSecurity")]
    pub fixes_security: bool,
}

/// A listing's checked releases, newest first.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseIndexEntry {
    pub slug: String,
    #[serde(rename = "releasesUrl")]
    pub releases_url: String,
    #[serde(default)]
    pub releases: Vec<IndexedRelease>,
}

/// A prompt the user dismissed for one listing's latest version.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dismissal {
    pub slug: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdatePrompt {
    pub slug: String,
    pub runtime: &'static str,
    #[serde(rename = "installedVersion")]
    pub installed_version: String,
    #[serde(rename = "latestVersion")]
    pub latest_version: String,
    pub urgent: bool,
    /// `security_fix` when a newer release fixes a high or critical finding,
    /// `installed_high_severity` when the installed release had one, else None.
    pub reason: Option<&'static str>,
    #[serde(rename = "releasesUrl")]
    pub releases_url: String,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct UpdateCheck {
    pub updates: Vec<UpdatePrompt>,
    pub dismissed: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Identifier<'a> {
    Numeric(u64),
    Text(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
struct Version<'a> {
    core: [u64; 3],
    pre: Vec<Identifier<'a>>,
}

/// `MAJOR.MINOR.PATCH[-pre][+build]`, with an optional leading `v`; None otherwise.
fn parse_version(value: &str) -> Option<Version<'_>> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let value = value.split('+').next()?;
    let (core, pre) = match value.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (value, None),
    };
    let mut parts = core.split('.');
    let mut numbers = [0u64; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *number = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => Vec::new(),
        Some(pre) => pre
            .split('.')
            .map(|part| {
                if part.is_empty() {
                    None
                } else if part.bytes().all(|b| b.is_ascii_digit()) {
                    part.parse().ok().map(Identifier::Numeric)
                } else {
                    Some(Identifier::Text(part))
                }
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Version { core: numbers, pre })
}

fn compare_identifiers(left: &Identifier<'_>, right: &Identifier<'_>) -> Ordering {
    match (left, right) {
        (Identifier::Numeric(a), Identifier::Numeric(b)) => a.cmp(b),
        (Identifier::Numeric(_), Identifier::Text(_)) => Ordering::Less,
        (Identifier::Text(_), Identifier::Numeric(_)) => Ordering::Greater,
        (Identifier::Text(a), Identifier::Text(b)) => a.cmp(b),
    }
}

/// Semantic-version precedence; None when either side is not a semantic version.
pub fn compare_versions(left: &str, right: &str) -> Option<Ordering> {
    let (left, right) = (parse_version(left)?, parse_version(right)?);
    let ordering = left.core.cmp(&right.core).then_with(|| {
        match (left.pre.is_empty(), right.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => left
                .pre
                .iter()
                .zip(&right.pre)
                .map(|(a, b)| compare_identifiers(a, b))
                .find(|ordering| ordering.is_ne())
                .unwrap_or_else(|| left.pre.len().cmp(&right.pre.len())),
        }
    });
    Some(ordering)
}

fn high_severity(release: &IndexedRelease) -> bool {
    matches!(release.max_severity.as_deref(), Some("high" | "critical"))
}

fn prompt_for(
    plugin: &InstalledPlugin,
    slug: &str,
    entry: &ReleaseIndexEntry,
) -> Option<UpdatePrompt> {
    let installed = plugin.version.as_deref()?;
    let newer: Vec<&IndexedRelease> = entry
        .releases
        .iter()
        .filter(|release| compare_versions(&release.version, installed) == Some(Ordering::Greater))
        .collect();
    let latest = newer.iter().copied().reduce(|best, release| {
        if compare_versions(&release.version, &best.version) == Some(Ordering::Greater) {
            release
        } else {
            best
        }
    })?;
    let installed_release = entry
        .releases
        .iter()
        .find(|release| compare_versions(&release.version, installed) == Some(Ordering::Equal));
    let reason = if newer.iter().any(|release| release.fixes_security) {
        Some("security_fix")
    } else if installed_release.is_some_and(high_severity) {
        Some("installed_high_severity")
    } else {
        None
    };
    Some(UpdatePrompt {
        slug: slug.to_owned(),
        runtime: plugin.runtime,
        installed_version: installed.to_owned(),
        latest_version: latest.version.clone(),
        urgent: reason.is_some(),
        reason,
        releases_url: entry.releases_url.clone(),
    })
}

/// One prompt per (listing, runtime) whose installed version is older than a
/// checked release, urgent prompts first, minus the ones the user dismissed
/// for that latest version.
pub fn check_updates(
    index: &[IndexEntry],
    releases: &[ReleaseIndexEntry],
    installed: &[InstalledPlugin],
    dismissed: &[Dismissal],
) -> UpdateCheck {
    let by_slug: BTreeMap<&str, &ReleaseIndexEntry> = releases
        .iter()
        .map(|entry| (entry.slug.as_str(), entry))
        .collect();
    let mut prompts: BTreeMap<(String, &'static str), UpdatePrompt> = BTreeMap::new();
    for plugin in installed {
        let Some(listing) = match_listing(index, plugin) else {
            continue;
        };
        let Some(entry) = by_slug.get(listing.slug.as_str()) else {
            continue;
        };
        if let Some(prompt) = prompt_for(plugin, &listing.slug, entry) {
            prompts
                .entry((listing.slug.clone(), plugin.runtime))
                .or_insert(prompt);
        }
    }
    let mut check = UpdateCheck::default();
    for prompt in prompts.into_values() {
        let hidden = dismissed.iter().any(|dismissal| {
            dismissal.slug == prompt.slug
                && compare_versions(&dismissal.version, &prompt.latest_version)
                    == Some(Ordering::Equal)
        });
        if hidden {
            check.dismissed += 1;
        } else {
            check.updates.push(prompt);
        }
    }
    check.updates.sort_by_key(|prompt| !prompt.urgent);
    check.updates.truncate(MAX_ENTRIES);
    check
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(slug: &str, repository: &str) -> IndexEntry {
        IndexEntry {
            slug: slug.to_owned(),
            repository: Some(repository.to_owned()),
            manifest_name: None,
            plugin_root: None,
        }
    }

    fn installed(repository: &str, version: Option<&str>) -> InstalledPlugin {
        InstalledPlugin {
            runtime: "claude-code",
            name: Some("demo".to_owned()),
            version: version.map(str::to_owned),
            repository: Some(repository.to_owned()),
        }
    }

    fn release(version: &str, severity: &str, fixes_security: bool) -> IndexedRelease {
        IndexedRelease {
            version: version.to_owned(),
            max_severity: Some(severity.to_owned()),
            fixes_security,
        }
    }

    fn releases(list: Vec<IndexedRelease>) -> Vec<ReleaseIndexEntry> {
        vec![ReleaseIndexEntry {
            slug: "demo".to_owned(),
            releases_url: "https://hol.org/plugins/demo/releases".to_owned(),
            releases: list,
        }]
    }

    const REPO: &str = "https://github.com/acme/demo";

    #[test]
    fn compares_semantic_versions() {
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Some(Ordering::Greater));
        assert_eq!(
            compare_versions("v1.2.3", "1.2.3+build"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare_versions("1.0.0-beta.2", "1.0.0-beta.11"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions("1.0.0-rc.1", "1.0.0"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_versions("1.0.0-alpha", "1.0.0-1"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_versions("1.0", "1.0.0"), None);
        assert_eq!(compare_versions("latest", "1.0.0"), None);
    }

    #[test]
    fn prompts_for_a_newer_checked_release() {
        let check = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "low", false),
                release("1.1.0", "none", false),
            ]),
            &[installed(REPO, Some("1.1.0"))],
            &[],
        );
        assert_eq!(check.updates.len(), 1);
        let prompt = &check.updates[0];
        assert_eq!(prompt.latest_version, "1.2.0");
        assert!(!prompt.urgent);
        assert_eq!(prompt.reason, None);
    }

    #[test]
    fn marks_security_fixes_and_high_severity_installs_urgent() {
        let fix = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "low", true),
                release("1.1.0", "critical", false),
            ]),
            &[installed(REPO, Some("1.0.0"))],
            &[],
        );
        assert_eq!(fix.updates[0].reason, Some("security_fix"));
        let installed_high = check_updates(
            &[listing("demo", REPO)],
            &releases(vec![
                release("1.2.0", "high", false),
                release("1.1.0", "high", false),
            ]),
            &[installed(REPO, Some("1.1.0"))],
            &[],
        );
        assert_eq!(
            installed_high.updates[0].reason,
            Some("installed_high_severity")
        );
        assert!(installed_high.updates[0].urgent);
    }

    #[test]
    fn skips_current_unversioned_unlisted_and_dismissed_plugins() {
        let index = [listing("demo", REPO)];
        let list = releases(vec![release("1.2.0", "none", false)]);
        let current = check_updates(&index, &list, &[installed(REPO, Some("1.2.0"))], &[]);
        assert!(current.updates.is_empty());
        let unversioned = check_updates(&index, &list, &[installed(REPO, None)], &[]);
        assert!(unversioned.updates.is_empty());
        let unlisted = check_updates(
            &index,
            &list,
            &[installed("https://github.com/acme/other", Some("0.1.0"))],
            &[],
        );
        assert!(unlisted.updates.is_empty());
        let dismissal = Dismissal {
            slug: "demo".to_owned(),
            version: "1.2.0".to_owned(),
        };
        let dismissed = check_updates(
            &index,
            &list,
            &[installed(REPO, Some("1.0.0"))],
            &[dismissal],
        );
        assert!(dismissed.updates.is_empty());
        assert_eq!(dismissed.dismissed, 1);
        let newer = releases(vec![
            release("1.3.0", "none", false),
            release("1.2.0", "none", false),
        ]);
        let reprompt = check_updates(
            &index,
            &newer,
            &[installed(REPO, Some("1.0.0"))],
            &[Dismissal {
                slug: "demo".to_owned(),
                version: "1.2.0".to_owned(),
            }],
        );
        assert_eq!(reprompt.updates[0].latest_version, "1.3.0");
    }
}
