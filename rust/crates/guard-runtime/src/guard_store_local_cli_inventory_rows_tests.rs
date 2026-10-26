//! How the inventory read packs declarations for the classifier: what travels,
//! what is left undescribed, and the bounds every page stays under.
//!
//! Python's transport mirror pages by serialized bytes as well as by item
//! count, so a connector whose commands repeat one large stored schema never
//! builds a page the op would refuse. These pin the same two bounds here.

use guard_contracts::{
    McpClassificationRequestV1, MCP_CLASSIFICATION_MAX_BYTES, MCP_CLASSIFICATION_MAX_ITEMS,
    MCP_CLASSIFICATION_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::guard_store_local_cli_inventory_rows::{classifications, pack, Page};

/// A declaration carrying roughly `kibibytes` of transportable schema. The
/// filler is split across fields because one collection may hold only so many
/// items, and each string stays inside the per-string limit, so the schema is
/// large without being refused by the parser.
fn declaration(name: &str, kibibytes: usize) -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_owned(), Value::from("object"));
    let mut remaining = kibibytes;
    let mut field = 0;
    while remaining > 0 {
        let width = remaining.min(2048);
        let filler: Vec<Value> = (0..width).map(|_| Value::from("x".repeat(1024))).collect();
        schema.insert(format!("filler{field}"), Value::Array(filler));
        remaining -= width;
        field += 1;
    }
    json!({ "name": name, "inputSchema": Value::Object(schema) })
}

/// Serialized size of the request a packed page becomes.
fn page_bytes(page: &Page) -> usize {
    let request = McpClassificationRequestV1 {
        schema: MCP_CLASSIFICATION_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        items: page.items.clone(),
    };
    serde_json::to_vec(&request).unwrap().len()
}

#[test]
fn a_declaration_no_page_can_carry_is_left_undescribed() {
    let first = declaration("first", 1);
    let huge = declaration("huge", 8192);
    let last = declaration("last", 1);
    let definitions = [&first, &huge, &last];

    let pages = pack(&definitions);
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].indices, vec![0, 2]);

    let described = classifications(&definitions);
    assert!(!described[0].is_null(), "{described:?}");
    assert!(described[1].is_null(), "{described:?}");
    assert!(!described[2].is_null(), "{described:?}");
}

#[test]
fn large_declarations_split_into_pages_under_the_byte_budget() {
    let owned: Vec<Value> = (0..4)
        .map(|index| declaration(&format!("tool{index}"), 2048))
        .collect();
    let definitions: Vec<&Value> = owned.iter().collect();

    let pages = pack(&definitions);
    let count = pages.len();
    assert!(
        count >= 2,
        "four large declarations packed into {count} page"
    );
    for page in &pages {
        let bytes = page_bytes(page);
        assert!(
            bytes <= MCP_CLASSIFICATION_MAX_BYTES,
            "page of {bytes} bytes"
        );
    }
    let order: Vec<usize> = pages.iter().flat_map(|page| page.indices.clone()).collect();
    assert_eq!(order, vec![0, 1, 2, 3]);

    let described = classifications(&definitions);
    assert!(described.iter().all(|entry| !entry.is_null()));
}

#[test]
fn the_item_cap_still_closes_a_page_of_small_declarations() {
    let owned: Vec<Value> = (0..=MCP_CLASSIFICATION_MAX_ITEMS)
        .map(|index| json!({ "name": format!("tool{index}") }))
        .collect();
    let definitions: Vec<&Value> = owned.iter().collect();

    let pages = pack(&definitions);
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].items.len(), MCP_CLASSIFICATION_MAX_ITEMS);
    assert_eq!(pages[1].indices, vec![MCP_CLASSIFICATION_MAX_ITEMS]);

    let described = classifications(&definitions);
    assert!(described.iter().all(|entry| !entry.is_null()));
}
