//! A workspace can resolve one package to several versions: two lockfiles in
//! a monorepo, or a nested npm copy under another package. Each resolved
//! version is audited on its own, so none of them may be folded into another.

use super::*;
use serde_json::json;

fn item(name: &str, direct: bool, range: Value, version: Value) -> Map<String, Value> {
    json!({
        "ecosystem": "npm",
        "namespace": null,
        "name": name,
        "direct": direct,
        "range": range,
        "version": version,
    })
    .as_object()
    .unwrap()
    .clone()
}

fn merged(items: &[Map<String, Value>]) -> Vec<Value> {
    let mut inventory = InventoryMap::new();
    for item in items {
        merge_inventory_item(&mut inventory, item);
    }
    inventory
        .into_values()
        .into_iter()
        .map(Value::Object)
        .collect()
}

#[test]
fn a_second_resolved_version_keeps_its_own_item() {
    let items = merged(&[
        item("lodash", false, json!(null), json!("4.17.21")),
        item("lodash", false, json!(null), json!("4.17.15")),
        item("lodash", false, json!(null), json!("4.17.15")),
    ]);
    assert_eq!(
        items,
        vec![
            Value::Object(item("lodash", false, json!(null), json!("4.17.21"))),
            Value::Object(item("lodash", false, json!(null), json!("4.17.15"))),
        ]
    );
}

#[test]
fn a_manifest_range_takes_the_first_resolved_version() {
    let items = merged(&[
        item("lodash", true, json!("^4"), json!(null)),
        item("lodash", false, json!(null), json!("4.17.21")),
        item("lodash", false, json!(null), json!("4.17.15")),
        item("lodash", false, json!(null), json!("4.17.21")),
    ]);
    assert_eq!(
        items,
        vec![
            Value::Object(item("lodash", true, json!("^4"), json!("4.17.21"))),
            Value::Object(item("lodash", false, json!(null), json!("4.17.15"))),
        ]
    );
}

#[test]
fn an_item_without_a_version_still_merges_into_the_first() {
    let items = merged(&[
        item("lodash", false, json!(null), json!("4.17.21")),
        item("lodash", true, json!("^4"), json!(null)),
        item("lodash", false, json!(null), json!("")),
    ]);
    assert_eq!(
        items,
        vec![Value::Object(item(
            "lodash",
            true,
            json!("^4"),
            json!("4.17.21")
        ))]
    );
}

#[test]
fn a_nested_package_lock_entry_is_named_after_its_package() {
    assert_eq!(
        dependency_name("npm", "a/node_modules/minimist"),
        (None, "minimist".to_owned())
    );
    assert_eq!(
        dependency_name("npm", "@s/x/node_modules/@t/y"),
        (Some("@t".to_owned()), "y".to_owned())
    );
    assert_eq!(
        dependency_name("npm", "@s/x/node_modules/b/node_modules/c"),
        (None, "c".to_owned())
    );
    assert_eq!(
        dependency_name("npm", "@scope/pkg"),
        (Some("@scope".to_owned()), "pkg".to_owned())
    );
}

#[test]
fn a_go_module_path_keeps_its_node_modules_segment() {
    assert_eq!(
        dependency_name("go", "github.com/acme/node_modules/tool"),
        (None, "github.com/acme/node_modules/tool".to_owned())
    );
    assert_eq!(
        split_namespace_name("github.com/acme/node_modules/tool"),
        (None, "github.com/acme/node_modules/tool".to_owned())
    );
}

#[test]
fn a_lockfile_entry_its_own_manifest_lists_is_direct() {
    let mut direct = DirectDependencies::default();
    direct.record(
        "packages/app/package.json",
        "npm",
        "lodash",
        Some("^3".into()),
    );
    direct.record("package.json", "npm", "lodash", Some("^4".into()));
    direct.record("package.json", "npm", "lodash", Some("^5".into()));

    assert_eq!(
        direct.lockfile_range("packages/app/package-lock.json", "npm", "lodash"),
        Some(Some("^3".into()))
    );
    assert_eq!(
        direct.lockfile_range("package-lock.json", "npm", "lodash"),
        Some(Some("^4".into()))
    );
    // A copy nested under another package, another ecosystem or a lockfile
    // with no manifest beside it is not direct.
    assert_eq!(
        direct.lockfile_range("package-lock.json", "npm", "a/node_modules/lodash"),
        None
    );
    assert_eq!(direct.lockfile_range("Cargo.lock", "cargo", "lodash"), None);
    assert_eq!(
        direct.lockfile_range("packages/web/package-lock.json", "npm", "lodash"),
        None
    );
}
