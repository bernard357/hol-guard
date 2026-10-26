//! Paging the local CLI inventory read: a device holding more connectors than
//! one reply may frame still lists every one of them, because the caller walks
//! the offsets the pages name.

use serde_json::{Map, Value};

use crate::guard_store_local_cli_inventory::inventory_page;

/// An item of roughly `kibibytes`, so that only a few fit one page.
fn bulky_item(index: usize, kibibytes: usize) -> Map<String, Value> {
    let mut item = Map::new();
    item.insert(
        "cli_id".to_owned(),
        Value::from(format!("local-cli.{index:03}")),
    );
    item.insert(
        "filler".to_owned(),
        Value::from("x".repeat(kibibytes * 1024)),
    );
    item
}

/// Every `cli_id` a caller sees when it reads page by page, as the Python
/// store does.
fn walk(items: &[Map<String, Value>]) -> Vec<String> {
    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let reply = inventory_page(items.to_vec(), offset);
        let listed = reply["items"].as_array().expect("items").clone();
        assert!(!listed.is_empty(), "a page must advance past its offset");
        for item in &listed {
            seen.push(item["cli_id"].as_str().expect("cli_id").to_owned());
        }
        offset += listed.len();
        match reply["next_offset"].as_u64() {
            None => return seen,
            Some(next) => assert_eq!(usize::try_from(next).expect("offset"), offset),
        }
    }
}

#[test]
fn walking_the_pages_lists_every_connector() {
    let items: Vec<Map<String, Value>> = (0..80).map(|index| bulky_item(index, 64)).collect();
    // 80 items of 64 KiB are past one reply, so this really takes several
    // pages rather than proving the single-page case twice.
    assert!(inventory_page(items.clone(), 0)["next_offset"]
        .as_u64()
        .is_some());
    let walked = walk(&items);
    assert_eq!(walked.len(), items.len());
    assert_eq!(walked.first().map(String::as_str), Some("local-cli.000"));
    assert_eq!(walked.last().map(String::as_str), Some("local-cli.079"));
}

#[test]
fn an_item_larger_than_one_page_still_comes_back() {
    let reply = inventory_page(vec![bulky_item(0, 4096), bulky_item(1, 1)], 0);
    assert_eq!(reply["items"].as_array().expect("items").len(), 1);
    assert_eq!(reply["next_offset"].as_u64(), Some(1));
}

#[test]
fn an_offset_past_the_last_item_ends_the_walk() {
    let reply = inventory_page(vec![bulky_item(0, 1)], 5);
    assert!(reply["items"].as_array().expect("items").is_empty());
    assert!(reply["next_offset"].is_null());
}
