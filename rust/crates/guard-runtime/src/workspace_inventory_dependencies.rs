//! Dependency maps of workspace manifests and lockfiles, and the inventory
//! rows they contribute.

use std::collections::HashMap;
use std::path::Path;

use guard_command::dep_map::DepMap;
use guard_command::package_manifest_diff::{
    installs_every_version, parse_manifest_dependencies_ordered,
};
use guard_command::workspace_inventory::{
    dependency_name, merge_inventory_item, python_strip, DirectDependencies, InventoryMap,
};
use serde_json::{json, Map, Value};

use crate::workspace_inventory_files::read_workspace_audit_text;

pub(crate) const MANIFEST_BYTE_LIMIT: usize = 2_097_152;
pub(crate) const MANIFEST_DEADLINE_MS: u64 = 50;

pub(crate) fn item(
    ecosystem: &str,
    namespace: Option<String>,
    name: String,
    direct: bool,
    range: Option<String>,
    version: Option<String>,
) -> Map<String, Value> {
    let mut entry = Map::new();
    entry.insert("ecosystem".into(), json!(ecosystem));
    entry.insert("namespace".into(), json!(namespace));
    entry.insert("name".into(), json!(name));
    entry.insert("direct".into(), json!(direct));
    entry.insert("range".into(), json!(range));
    entry.insert("version".into(), json!(version));
    entry
}

pub(crate) fn stripped_or_none(version: &str) -> Option<String> {
    let stripped = python_strip(version);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// Dependency maps keyed by workspace-relative path, parsed at most once.
pub(crate) struct DependencyReader<'a> {
    workspace: &'a Path,
    cache: HashMap<String, Option<DepMap>>,
}

impl<'a> DependencyReader<'a> {
    pub(crate) fn new(workspace: &'a Path) -> Self {
        Self {
            workspace,
            cache: HashMap::new(),
        }
    }

    /// `None` when the file cannot be read for audit; otherwise the parse.
    pub(crate) fn dependencies(&mut self, path: &str) -> Option<&DepMap> {
        let workspace = self.workspace;
        self.cache
            .entry(path.to_owned())
            .or_insert_with(|| {
                let text = read_workspace_audit_text(workspace, path)?;
                Some(parse_manifest_dependencies_ordered(
                    path,
                    &text,
                    MANIFEST_BYTE_LIMIT,
                    MANIFEST_DEADLINE_MS,
                ))
            })
            .as_ref()
    }
}

pub(crate) fn merge_dependencies(
    inventory: &mut InventoryMap,
    reader: &mut DependencyReader<'_>,
    path: &str,
    ecosystem: &str,
    manifest: bool,
    direct_dependencies: &mut DirectDependencies,
) {
    let Some(dependencies) = reader.dependencies(path) else {
        return;
    };
    // Every copy such a lockfile resolves is installed, so each is listed.
    let every_version = !manifest && installs_every_version(path);
    for (package_name, version) in dependencies.iter() {
        let stripped = stripped_or_none(version);
        if manifest {
            direct_dependencies.record(path, ecosystem, package_name, stripped);
            continue;
        }
        let (namespace, name) = dependency_name(ecosystem, package_name);
        let (direct, range) =
            match direct_dependencies.lockfile_range(path, ecosystem, package_name) {
                Some(range) => (true, range),
                None => (false, None),
            };
        let entry = item(
            ecosystem,
            namespace.clone(),
            name.clone(),
            direct,
            range,
            stripped,
        );
        merge_inventory_item(inventory, &entry);
        let earlier = if every_version {
            dependencies.earlier(package_name)
        } else {
            &[]
        };
        for version in earlier {
            let entry = item(
                ecosystem,
                namespace.clone(),
                name.clone(),
                false,
                None,
                stripped_or_none(version),
            );
            merge_inventory_item(inventory, &entry);
        }
    }
}
