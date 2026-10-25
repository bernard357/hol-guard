//! Repository settings the Kit reads from the scanner's config file.
//!
//! `[plugin_kit] exclude_paths` names files that are not part of the plugin,
//! such as copies of its skills kept for other marketplaces. It is separate
//! from the scanner's `ignore_paths`, which only hides findings, so hiding a
//! finding never drops a skill or server from a package.

use std::path::Path;

use crate::walk;

const CONFIG_FILES: &[&str] = &[".plugin-scanner.toml", ".codex-plugin-scanner.toml"];
const MAX_PATTERNS: usize = 64;
const MAX_PATTERN_LENGTH: usize = 256;

/// Glob patterns from the first config file present. `*` matches any run of
/// characters, `/` included, and `?` matches one character, as in the
/// scanner's `ignore_paths`.
pub(crate) fn exclude_paths(root: &Path) -> Result<Vec<String>, String> {
    let Some(text) = CONFIG_FILES
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())
        .map(|path| walk::read_text(&path).ok_or("plugin_kit_config_invalid"))
        .transpose()?
    else {
        return Ok(Vec::new());
    };
    let document: toml::Table = text.parse().map_err(|_| "plugin_kit_config_invalid")?;
    let Some(section) = document.get("plugin_kit") else {
        return Ok(Vec::new());
    };
    let patterns = section
        .get("exclude_paths")
        .map(|value| value.as_array().ok_or("plugin_kit_config_invalid"))
        .transpose()?
        .map(Vec::as_slice)
        .unwrap_or_default();
    if patterns.len() > MAX_PATTERNS {
        return Err("plugin_kit_config_invalid".to_owned());
    }
    patterns
        .iter()
        .map(|value| match value.as_str() {
            Some(pattern) if !pattern.is_empty() && pattern.len() <= MAX_PATTERN_LENGTH => {
                Ok(pattern.trim_start_matches("./").to_owned())
            }
            _ => Err("plugin_kit_config_invalid".to_owned()),
        })
        .collect()
}

/// Whether `path`, relative to the repository root with `/` separators,
/// matches `pattern`.
pub(crate) fn matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    let (mut p, mut s) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while s < path.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, s));
                p += 1;
            }
            Some(&c) if c == '?' || c == path[s] => {
                p += 1;
                s += 1;
            }
            _ => match star {
                Some((star_p, star_s)) => {
                    p = star_p + 1;
                    s = star_s + 1;
                    star = Some((star_p, star_s + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn patterns_match_like_the_scanner_ignore_paths() {
        assert!(matches(
            "distributions/*",
            "distributions/a/skills/x/SKILL.md"
        ));
        assert!(matches("*.md", "docs/guide.md"));
        assert!(matches("skill-?/SKILL.md", "skill-a/SKILL.md"));
        assert!(matches("README.md", "README.md"));
        assert!(!matches("distributions/*", "skills/x/SKILL.md"));
        assert!(!matches("skill-?/SKILL.md", "skill-ab/SKILL.md"));
        assert!(!matches("README.md", "docs/README.md"));
    }
}
