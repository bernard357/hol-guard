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
        split_namespace_name("a/node_modules/minimist"),
        (None, "minimist".to_owned())
    );
    assert_eq!(
        split_namespace_name("@s/x/node_modules/@t/y"),
        (Some("@t".to_owned()), "y".to_owned())
    );
    assert_eq!(
        split_namespace_name("@s/x/node_modules/b/node_modules/c"),
        (None, "c".to_owned())
    );
    assert_eq!(
        split_namespace_name("@scope/pkg"),
        (Some("@scope".to_owned()), "pkg".to_owned())
    );
}
