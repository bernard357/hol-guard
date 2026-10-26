//! Row normalization, suggestion ranking and the classification transport
//! mirror behind the local CLI inventory read.
//!
//! Everything here is shape work: which stored cells become which item field,
//! which declarations can travel to the classifier, and how the classifier's
//! answers come back in request order. No verdict is decided here; ranking
//! and classification are the in-crate evaluators' answers.

use guard_contracts::{
    McpClassificationItemV1, McpClassificationRequestV1, SuggestionToolV1,
    MCP_CLASSIFICATION_MAX_ITEMS, MCP_CLASSIFICATION_REQUEST_SCHEMA,
};
use serde_json::{Map, Value};

use crate::custom_extension_suggestion::suggestion_verdicts;
use crate::guard_store_db::Row;
use crate::guard_store_json::py_str;
use crate::mcp_classification_op::evaluate;

/// `_SUGGESTION_BATCH`: source paths can be long, so stay well inside the
/// native batch limits.
const SUGGESTION_BATCH: usize = 256;
/// `_COUNT_LIMIT`: the native request carries observed counts as signed
/// 64-bit integers.
const COUNT_LIMIT: i64 = 1 << 62;

/// `_MAX_JSON_STRING_BYTES` of the Python transport mirror.
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;
/// `_MAX_JSON_COLLECTION_ITEMS` of the Python transport mirror.
const MAX_JSON_COLLECTION_ITEMS: usize = 4096;
/// `_MAX_ITEM_DEPTH`: the envelope already spends four levels before an
/// item's own fields.
const MAX_ITEM_DEPTH: usize = 32 - 4;

const SURFACES: [&str; 3] = ["cli", "mcp", "package-scripts"];
const MAX_DECLARED_SOURCES: usize = 16;

/// `_observation_from_row`: one observation row as a displayed item.
pub(crate) fn observation_item(row: &Row) -> Map<String, Value> {
    let get = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    let identity_hash = get("identity_hash");
    let server_identity_hash = get("server_identity_hash");
    let surface = match get("surface") {
        Value::String(text) if SURFACES.contains(&text.as_str()) => text,
        _ => "cli".to_owned(),
    };
    let mut item = Map::new();
    item.insert("cli_id".to_owned(), get("cli_id"));
    item.insert("identity_hash".to_owned(), identity_hash.clone());
    item.insert("kind".to_owned(), get("kind"));
    item.insert("name".to_owned(), get("name"));
    item.insert("interpreter_name".to_owned(), get("interpreter_name"));
    item.insert("example_label".to_owned(), get("example_label"));
    item.insert("observed_count".to_owned(), get("observed_count"));
    item.insert("last_seen_at".to_owned(), get("last_seen_at"));
    item.insert("source_path".to_owned(), get("source_path"));
    item.insert("help_status".to_owned(), get("help_status"));
    item.insert("surface".to_owned(), Value::from(surface.clone()));
    item.insert(
        "server_identity_hash".to_owned(),
        server_identity_hash.clone(),
    );
    item.insert(
        "source_label".to_owned(),
        match get("source_label") {
            Value::String(label) if !label.is_empty() => Value::from(label),
            _ => Value::Null,
        },
    );
    if surface == "mcp" {
        item.insert(
            "permission_scope".to_owned(),
            Value::from(permission_scope(
                &get("server_command"),
                &identity_hash,
                &server_identity_hash,
            )),
        );
        declaration(
            &mut item,
            &get("remote_origin"),
            &get("declared_sources_json"),
        );
    }
    item
}

/// A server command naming an observed connection is a host namespace; a
/// distinct server identity is a configured connection; anything else is a
/// record from before either was written.
fn permission_scope(
    server_command: &Value,
    identity_hash: &Value,
    server_identity_hash: &Value,
) -> &'static str {
    if server_command
        .as_str()
        .is_some_and(|command| command.starts_with("observed-mcp:"))
    {
        return "host-namespace";
    }
    if !server_identity_hash.is_null() && identity_hash != server_identity_hash {
        return "configured-connection";
    }
    "legacy-device"
}

/// `_declaration`: which harness configs declare an MCP connector; a remote
/// one adds its origin.
fn declaration(
    item: &mut Map<String, Value>,
    remote_origin: &Value,
    declared_sources_json: &Value,
) {
    let mut sources: Vec<Value> = Vec::new();
    if let Some(raw) = declared_sources_json.as_str() {
        if let Ok(Value::Array(decoded)) = serde_json::from_str::<Value>(raw) {
            sources = decoded
                .into_iter()
                .filter(Value::is_string)
                .take(MAX_DECLARED_SOURCES)
                .collect();
        }
    }
    item.insert("declared_sources".to_owned(), Value::Array(sources));
    if let Some(origin) = remote_origin.as_str() {
        if !origin.is_empty() {
            item.insert("remote_origin".to_owned(), Value::from(origin));
        }
    }
}

/// `_merge_item`: an observation plus the device grant that covers it.
pub(crate) fn merge_item(
    mut observation: Map<String, Value>,
    grant: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    let (state, stale, revision) = match grant {
        None => (Value::from("unset"), Value::from(false), Value::Null),
        Some(grant) => {
            let granted = grant.get("identity_hash").map(py_text);
            let observed = observation.get("identity_hash").map(py_text);
            (
                Value::from(grant.get("state").map(py_text).unwrap_or_default()),
                Value::from(granted != observed),
                grant.get("revision").cloned().unwrap_or(Value::Null),
            )
        }
    };
    observation.insert("state".to_owned(), state);
    observation.insert("stale".to_owned(), stale);
    observation.insert("grant_revision".to_owned(), revision);
    observation
}

/// `str(value)` of a cell, for the comparisons Python makes on text.
pub(crate) fn py_text(value: &Value) -> String {
    py_str(value).unwrap_or_default()
}

/// `_with_suggestions`: rank items in bounded batches. An item the ranker
/// cannot describe stays hidden rather than being ranked here.
pub(crate) fn with_suggestions(items: &mut [Map<String, Value>]) {
    let mut ranked: Vec<usize> = Vec::new();
    let mut tools: Vec<SuggestionToolV1> = Vec::new();
    for (index, item) in items.iter_mut().enumerate() {
        item.insert("suggestion_score".to_owned(), Value::from(0));
        item.insert("suggestable".to_owned(), Value::from(false));
        let (Some(kind), Some(name)) = (
            item.get("kind").and_then(Value::as_str),
            item.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        tools.push(SuggestionToolV1 {
            name: name.to_owned(),
            kind: if kind == "script" {
                "script"
            } else {
                "executable"
            }
            .to_owned(),
            source_path: item
                .get("source_path")
                .and_then(Value::as_str)
                .map(str::to_owned),
            observed_count: observed_count(item.get("observed_count")),
            help_status: item
                .get("help_status")
                .and_then(Value::as_str)
                .map(str::to_owned),
            surface: item
                .get("surface")
                .and_then(Value::as_str)
                .unwrap_or("cli")
                .to_owned(),
        });
        ranked.push(index);
    }
    for (chunk, batch) in ranked.chunks(SUGGESTION_BATCH).enumerate() {
        let offset = chunk * SUGGESTION_BATCH;
        let Ok(verdicts) = suggestion_verdicts(&tools[offset..offset + batch.len()]) else {
            continue;
        };
        for (index, verdict) in batch.iter().zip(verdicts) {
            items[*index].insert("suggestion_score".to_owned(), Value::from(verdict.score));
            items[*index].insert("suggestable".to_owned(), Value::from(verdict.suggestable));
        }
    }
}

/// `suggestion_tool`'s clamp: a stored count outside the signed range the
/// native request carries is pinned, not refused.
fn observed_count(value: Option<&Value>) -> i64 {
    let Some(count) = value.and_then(Value::as_i64) else {
        return 0;
    };
    count.clamp(-COUNT_LIMIT, COUNT_LIMIT)
}

/// `classify_mcp_actions`: describe each declaration in request order.
///
/// A declaration the classifier's parser would refuse comes back `null`, the
/// same undescribed answer Python's transport mirror produces, so one
/// oversized provider schema never costs the rest of the batch its
/// descriptions.
pub(crate) fn classifications(definitions: &[&Value]) -> Vec<Value> {
    let mut described = vec![Value::Null; definitions.len()];
    let mut sendable: Vec<usize> = Vec::new();
    let mut items: Vec<McpClassificationItemV1> = Vec::new();
    for (index, definition) in definitions.iter().enumerate() {
        let name = definition.get("name").map(py_text).unwrap_or_default();
        let schema = definition.get("inputSchema").cloned();
        let annotations = definition.get("annotations").cloned();
        if !transportable(&name, 1)
            || !optional_transportable(schema.as_ref())
            || !optional_transportable(annotations.as_ref())
        {
            continue;
        }
        sendable.push(index);
        items.push(McpClassificationItemV1 {
            name,
            schema,
            provider: None,
            annotations,
            full_schema: true,
        });
    }
    for (page, chunk) in sendable.chunks(MCP_CLASSIFICATION_MAX_ITEMS).enumerate() {
        let offset = page * MCP_CLASSIFICATION_MAX_ITEMS;
        let request = McpClassificationRequestV1 {
            schema: MCP_CLASSIFICATION_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            items: items[offset..offset + chunk.len()].to_vec(),
        };
        let Ok(payload) = evaluate(&request) else {
            // Python raises here and the caller keeps the items it already
            // built, undescribed; describing them from a partial answer is
            // the one thing neither side may do.
            return vec![Value::Null; definitions.len()];
        };
        let Some(Value::Array(reply)) = payload.get("classifications").cloned() else {
            return vec![Value::Null; definitions.len()];
        };
        if reply.len() != chunk.len() {
            return vec![Value::Null; definitions.len()];
        }
        for (index, entry) in chunk.iter().zip(reply) {
            described[*index] = entry;
        }
    }
    described
}

fn optional_transportable(value: Option<&Value>) -> bool {
    value.is_none_or(|value| transportable_value(value, 1))
}

/// `_transportable` for a string field of the item itself.
fn transportable(text: &str, depth: usize) -> bool {
    depth <= MAX_ITEM_DEPTH && text.len() <= MAX_JSON_STRING_BYTES
}

/// `_transportable`: whether the classifier's parser would accept this
/// declaration. A provider schema can carry a megabyte-long description, an
/// integer outside the JSON number range or a non-finite float; the parser
/// refuses the whole frame over any of them.
fn transportable_value(value: &Value, depth: usize) -> bool {
    if depth > MAX_ITEM_DEPTH {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::String(text) => transportable(text, depth),
        Value::Number(number) => {
            let literal = number.to_string();
            if literal.contains(['.', 'e', 'E']) {
                number.as_f64().is_some_and(f64::is_finite)
            } else {
                number.as_i64().is_some() || number.as_u64().is_some()
            }
        }
        Value::Array(entries) => {
            entries.len() <= MAX_JSON_COLLECTION_ITEMS
                && entries
                    .iter()
                    .all(|entry| transportable_value(entry, depth + 1))
        }
        Value::Object(fields) => {
            fields.len() <= MAX_JSON_COLLECTION_ITEMS
                && fields.iter().all(|(key, entry)| {
                    transportable(key, depth) && transportable_value(entry, depth + 1)
                })
        }
    }
}
