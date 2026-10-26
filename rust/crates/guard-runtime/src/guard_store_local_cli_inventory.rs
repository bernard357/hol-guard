//! The local CLI inventory read: every observed connector and every device
//! grant, as one list the surfaces render.
//!
//! The Python caller ran a schema ensure before reading, so a store that
//! predates a column still answered. This read never writes, so a missing
//! table reads as no rows and a missing column reads as null, which is the
//! same inventory that ensure would have produced.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, value_error, Row, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::guard_store_local_cli_inventory_rows::{
    classifications, merge_item, observation_item, py_text, with_suggestions,
};
use crate::guard_store_local_cli_mcp_snapshot::decode_snapshot;

/// The observation columns the item shape needs, in `_observation_from_row`
/// order.
const OBSERVATION_COLUMNS: [&str; 16] = [
    "cli_id",
    "identity_hash",
    "kind",
    "name",
    "interpreter_name",
    "example_label",
    "observed_count",
    "last_seen_at",
    "source_path",
    "help_status",
    "surface",
    "server_identity_hash",
    "source_label",
    "server_command",
    "remote_origin",
    "declared_sources_json",
];

/// `LOCAL_CLI_CAPABILITIES`.
const CAPABILITIES: [&str; 3] = ["loopback-network", "state-dir-read", "state-dir-write"];

/// `CAPABILITY_BY_CAUSE`: the capability a recorded blocked cause points at.
const CAPABILITY_BY_CAUSE: [(&str, &str); 3] = [
    ("connect_loopback", "loopback-network"),
    ("read_home_state", "state-dir-read"),
    ("write_home_state", "state-dir-write"),
];

const GRANT_ONLY_PREFIX: &str = "local-cli.";

/// `list_local_cli_items`: observations merged with grants, ranked,
/// capability-annotated and, for MCP connectors, described.
pub(crate) fn list_items(connection: &Connection, _args: &Args) -> StoreResult<Value> {
    let observation_rows = observations(connection)?;
    let grant_rows = grants(connection)?;
    let authority_revision = authority_revision(connection)?;
    let mut command_map = commands_by_cli(connection)?;
    let catalog_map = mcp_catalogs(connection)?;
    let provider_map = provider_summaries(connection)?;
    let capability_rows = capabilities(connection)?;
    let implied = implied_capabilities(connection)?;

    let mut items: Vec<Map<String, Value>> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for row in &observation_rows {
        let item = observation_item(row);
        let cli_id = item.get("cli_id").map(py_text).unwrap_or_default();
        seen.insert(cli_id.clone());
        items.push(merge_item(item, grant_rows.get(&cli_id)));
    }
    for (cli_id, grant) in &grant_rows {
        if seen.contains(cli_id) {
            continue;
        }
        items.push(grant_only_item(cli_id, grant));
    }

    with_suggestions(&mut items);
    mark_shared_enrolled_servers(&mut items, &grant_rows);

    let mut undescribed: Vec<(usize, usize, Value)> = Vec::new();
    for (index, item) in items.iter_mut().enumerate() {
        let cli_id = item.get("cli_id").map(py_text).unwrap_or_default();
        item.insert(
            "authority_revision".to_owned(),
            Value::from(authority_revision),
        );
        let commands = command_map.remove(&cli_id).unwrap_or_default();
        let surface_is_cli = item.get("surface").and_then(Value::as_str) == Some("cli");
        item.insert(
            "capabilities".to_owned(),
            if surface_is_cli {
                capability_map(capability_rows.get(&cli_id))
            } else {
                Value::Object(Map::new())
            },
        );
        if let Some(capability) = suggested_capability(item, implied.get(&cli_id)) {
            item.insert("suggested_capability".to_owned(), Value::from(capability));
        }
        if let Some((identity_hash, payload)) = catalog_map.get(&cli_id) {
            if is_mcp(item)
                && item.get("identity_hash").and_then(Value::as_str) == Some(identity_hash.as_str())
            {
                item.insert("mcp_catalog".to_owned(), payload.clone());
                let by_name = tools_by_name(payload);
                for (position, command) in commands.iter().enumerate() {
                    let Some(usage) = command.get("usage") else {
                        continue;
                    };
                    let Some(definition) = usage.as_str().and_then(|usage| by_name.get(usage))
                    else {
                        continue;
                    };
                    undescribed.push((index, position, (*definition).clone()));
                }
            }
        }
        item.insert(
            "commands".to_owned(),
            Value::Array(commands.into_iter().map(Value::Object).collect()),
        );
        if let Some(summary) = provider_map.get(&cli_id) {
            item.insert("provider_catalog".to_owned(), summary.clone());
        }
    }

    let definitions: Vec<&Value> = undescribed
        .iter()
        .map(|(_, _, definition)| definition)
        .collect();
    let described = classifications(&definitions);
    for ((index, position, _), classification) in undescribed.iter().zip(described) {
        if classification.is_null() {
            continue;
        }
        let Some(Value::Array(commands)) = items[*index].get_mut("commands") else {
            continue;
        };
        let Some(Value::Object(command)) = commands.get_mut(*position) else {
            continue;
        };
        command.insert("classification".to_owned(), classification);
    }

    Ok(Value::Array(items.into_iter().map(Value::Object).collect()))
}

/// Observation rows in display order, with the columns a store that predates
/// a migration does not have read as null.
fn observations(connection: &Connection) -> StoreResult<Vec<Row>> {
    if !table_exists(connection, "local_cli_observation")? {
        return Ok(Vec::new());
    }
    let present = column_names(connection, "local_cli_observation")?;
    let projection = OBSERVATION_COLUMNS
        .iter()
        .map(|column| {
            if present.contains(*column) {
                (*column).to_owned()
            } else {
                format!("null as {column}")
            }
        })
        .collect::<Vec<String>>()
        .join(", ");
    let order = if present.contains("last_seen_at") {
        "order by last_seen_at desc, cli_id asc"
    } else {
        "order by cli_id asc"
    };
    query_all(
        connection,
        &format!("select {projection} from local_cli_observation {order}"),
        &[],
    )
}

/// Device grants by CLI id. A grant row whose id is not text is a row no
/// surface can address, so the read refuses rather than listing it.
fn grants(connection: &Connection) -> StoreResult<BTreeMap<String, Map<String, Value>>> {
    let mut grants = BTreeMap::new();
    if !table_exists(connection, "local_cli_grant")? {
        return Ok(grants);
    }
    let rows = query_all(
        connection,
        "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant",
        &[],
    )?;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            return value_error("invalid local CLI row");
        };
        grants.insert(cli_id.to_owned(), row.clone());
    }
    Ok(grants)
}

fn authority_revision(connection: &Connection) -> StoreResult<i64> {
    if !table_exists(connection, "local_cli_authority")? {
        return Ok(0);
    }
    let row = query_one(
        connection,
        "select revision from local_cli_authority where singleton = 1",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(0);
    };
    match row.get("revision").and_then(Value::as_i64) {
        Some(revision) => Ok(revision),
        None => value_error("invalid local CLI row"),
    }
}

/// `_load_commands_by_cli`: catalog rows in display order with their stored
/// per-command state.
fn commands_by_cli(
    connection: &Connection,
) -> StoreResult<HashMap<String, Vec<Map<String, Value>>>> {
    let mut grouped: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    if !table_exists(connection, "local_cli_command")? {
        return Ok(grouped);
    }
    let mut states: HashMap<(String, String), String> = HashMap::new();
    if table_exists(connection, "local_cli_command_grant")? {
        for row in query_all(
            connection,
            "select cli_id, command_id, state from local_cli_command_grant",
            &[],
        )? {
            let (Some(cli_id), Some(command_id), Some(state)) = (
                row.get("cli_id").and_then(Value::as_str),
                row.get("command_id").and_then(Value::as_str),
                row.get("state").and_then(Value::as_str),
            ) else {
                continue;
            };
            states.insert((cli_id.to_owned(), command_id.to_owned()), state.to_owned());
        }
    }
    let rows = query_all(
        connection,
        "select cli_id, command_id, name, usage, description, parent_id \
         from local_cli_command order by cli_id asc, sort_index asc, command_id asc",
        &[],
    )?;
    for row in rows {
        let (Some(cli_id), Some(command_id)) = (
            row.get("cli_id").and_then(Value::as_str),
            row.get("command_id").and_then(Value::as_str),
        ) else {
            continue;
        };
        let state = states
            .get(&(cli_id.to_owned(), command_id.to_owned()))
            .map_or("inherit", String::as_str);
        let mut command = Map::new();
        command.insert("command_id".to_owned(), Value::from(command_id));
        for field in ["name", "usage", "description", "parent_id"] {
            command.insert(
                field.to_owned(),
                row.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        command.insert("state".to_owned(), Value::from(state));
        grouped.entry(cli_id.to_owned()).or_default().push(command);
    }
    Ok(grouped)
}

/// `load_mcp_catalogs`: the stored discovery snapshot, still bound to the
/// identity it was discovered for.
fn mcp_catalogs(connection: &Connection) -> StoreResult<HashMap<String, (String, Value)>> {
    let mut catalogs = HashMap::new();
    if !table_exists(connection, "local_mcp_catalog")? {
        return Ok(catalogs);
    }
    let rows = query_all(
        connection,
        "select cli_id, identity_hash, catalog_json, revision, updated_at, last_complete_at \
         from local_mcp_catalog",
        &[],
    )?;
    for row in rows {
        let Some(Value::Object(mut payload)) = decode_snapshot(row.get("catalog_json")) else {
            continue;
        };
        for field in ["revision", "updated_at", "last_complete_at"] {
            payload.insert(
                field.to_owned(),
                row.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        let cli_id = row.get("cli_id").map(py_text).unwrap_or_default();
        let identity_hash = row.get("identity_hash").map(py_text).unwrap_or_default();
        catalogs.insert(cli_id, (identity_hash, Value::Object(payload)));
    }
    Ok(catalogs)
}

/// `load_provider_catalog_summaries`: how much of a provider's action list
/// this device has seen. Coverage is a subset and the account is unverified;
/// both are stated so no surface reads the count as completeness.
fn provider_summaries(connection: &Connection) -> StoreResult<HashMap<String, Value>> {
    let mut summaries = HashMap::new();
    if !table_exists(connection, "local_mcp_provider_action")?
        || !table_exists(connection, "local_cli_observation")?
    {
        return Ok(summaries);
    }
    let rows = query_all(
        connection,
        "select p.cli_id as cli_id, count(*) as known_count, \
         sum(p.full_schema) as full_schema_count, max(p.updated_at) as updated_at \
         from local_mcp_provider_action p join local_cli_observation o \
         on p.cli_id = o.cli_id and p.identity_hash = o.identity_hash group by p.cli_id",
        &[],
    )?;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            continue;
        };
        summaries.insert(
            cli_id.to_owned(),
            json!({
                "provider": "composio",
                "known_count": row.get("known_count").cloned().unwrap_or(Value::Null),
                "full_schema_count": row.get("full_schema_count").cloned().unwrap_or(Value::Null),
                "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null),
                "coverage": "discovery-subset",
                "account_binding": "unverified",
            }),
        );
    }
    Ok(summaries)
}

/// `load_local_cli_capabilities`: only capabilities that are on, and only
/// names this build knows.
fn capabilities(connection: &Connection) -> StoreResult<HashMap<String, BTreeSet<String>>> {
    let mut stored: HashMap<String, BTreeSet<String>> = HashMap::new();
    if !table_exists(connection, "local_cli_grant_capability")? {
        return Ok(stored);
    }
    let rows = query_all(
        connection,
        "select cli_id, capability, state from local_cli_grant_capability",
        &[],
    )?;
    for row in rows {
        let Some(cli_id) = row.get("cli_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(capability) = row.get("capability").and_then(Value::as_str) else {
            continue;
        };
        if !CAPABILITIES.contains(&capability)
            || row.get("state").and_then(Value::as_str) != Some("on")
        {
            continue;
        }
        stored
            .entry(cli_id.to_owned())
            .or_default()
            .insert(capability.to_owned());
    }
    Ok(stored)
}

/// `capability_map`: the full map for one CLI, with absent capabilities off.
fn capability_map(enabled: Option<&BTreeSet<String>>) -> Value {
    let mut map = Map::new();
    for capability in CAPABILITIES {
        let on = enabled.is_some_and(|enabled| enabled.contains(capability));
        map.insert(
            capability.to_owned(),
            Value::from(if on { "on" } else { "off" }),
        );
    }
    Value::Object(map)
}

/// `implied_capabilities`: the capability each CLI's recorded blocked cause
/// points at, with the identity that cause was recorded for.
fn implied_capabilities(connection: &Connection) -> StoreResult<HashMap<String, (String, String)>> {
    let mut implied = HashMap::new();
    if !table_exists(connection, "local_cli_observation")?
        || !column_names(connection, "local_cli_observation")?.contains("first_blocked_cause")
    {
        return Ok(implied);
    }
    let rows = query_all(
        connection,
        "select cli_id, identity_hash, first_blocked_cause from local_cli_observation \
         where surface = 'cli' and first_blocked_cause in (?, ?, ?)",
        &CAPABILITY_BY_CAUSE.map(|(cause, _)| Value::from(cause)),
    )?;
    for row in rows {
        let cause = row
            .get("first_blocked_cause")
            .map(py_text)
            .unwrap_or_default();
        let Some((_, capability)) = CAPABILITY_BY_CAUSE
            .iter()
            .find(|(known, _)| *known == cause)
        else {
            continue;
        };
        implied.insert(
            row.get("cli_id").map(py_text).unwrap_or_default(),
            (
                row.get("identity_hash").map(py_text).unwrap_or_default(),
                (*capability).to_owned(),
            ),
        );
    }
    Ok(implied)
}

/// `_suggested_capability`: the capability an allowed CLI's recorded cause
/// points at while it is still off.
fn suggested_capability(
    item: &Map<String, Value>,
    implied: Option<&(String, String)>,
) -> Option<String> {
    let (identity_hash, capability) = implied?;
    if item.get("state").and_then(Value::as_str) != Some("allowed")
        || item.get("stale") == Some(&Value::Bool(true))
        || item.get("identity_hash").and_then(Value::as_str) != Some(identity_hash.as_str())
    {
        return None;
    }
    let on = item
        .get("capabilities")
        .and_then(Value::as_object)
        .and_then(|map| map.get(capability))
        .and_then(Value::as_str)
        == Some("on");
    if on {
        None
    } else {
        Some(capability.clone())
    }
}

/// `mark_shared_enrolled_servers`: flag un-enrolled MCP records kept because
/// an enrolled record shares their server.
fn mark_shared_enrolled_servers(
    items: &mut [Map<String, Value>],
    enrolled_ids: &BTreeMap<String, Map<String, Value>>,
) {
    let mut servers: BTreeSet<String> = BTreeSet::new();
    for item in items.iter() {
        if !is_mcp(item) || !enrolled(item, enrolled_ids) {
            continue;
        }
        let server = item
            .get("server_identity_hash")
            .filter(|value| truthy(value))
            .or_else(|| item.get("identity_hash"));
        let Some(server) = server.filter(|value| !value.is_null()) else {
            continue;
        };
        if let Some(key) = dumps_sorted(server) {
            servers.insert(key);
        }
    }
    let shares: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, item)| {
            is_mcp(item)
                && !enrolled(item, enrolled_ids)
                && item
                    .get("server_identity_hash")
                    .and_then(dumps_sorted)
                    .is_some_and(|key| servers.contains(&key))
        })
        .map(|(index, _)| index)
        .collect();
    for index in shares {
        items[index].insert("shares_enrolled_server".to_owned(), Value::from(true));
    }
}

/// An MCP record is the only kind a shared server can cover.
fn is_mcp(item: &Map<String, Value>) -> bool {
    item.get("surface").and_then(Value::as_str) == Some("mcp")
}

/// Whether this record's own CLI id carries a device grant.
fn enrolled(
    item: &Map<String, Value>,
    enrolled_ids: &BTreeMap<String, Map<String, Value>>,
) -> bool {
    item.get("cli_id")
        .and_then(Value::as_str)
        .is_some_and(|cli_id| enrolled_ids.contains_key(cli_id))
}

/// Python's truth test on a stored cell: null, an empty string and zero all
/// fall back to the connector's own identity.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::String(text) => !text.is_empty(),
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::Array(entries) => !entries.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// A grant with no observation still lists, so a device decision never
/// disappears because its connector has not been seen again.
fn grant_only_item(cli_id: &str, grant: &Map<String, Value>) -> Map<String, Value> {
    let label = cli_id.strip_prefix(GRANT_ONLY_PREFIX).unwrap_or(cli_id);
    let mut item = Map::new();
    item.insert("cli_id".to_owned(), Value::from(cli_id));
    item.insert("name".to_owned(), Value::from(label));
    item.insert("kind".to_owned(), Value::from("executable"));
    item.insert(
        "identity_hash".to_owned(),
        grant.get("identity_hash").cloned().unwrap_or(Value::Null),
    );
    item.insert("example_label".to_owned(), Value::from(label));
    item.insert("interpreter_name".to_owned(), Value::Null);
    item.insert("observed_count".to_owned(), Value::from(0));
    item.insert("last_seen_at".to_owned(), Value::Null);
    item.insert("source_path".to_owned(), Value::Null);
    item.insert("help_status".to_owned(), Value::Null);
    item.insert("surface".to_owned(), Value::from("cli"));
    item.insert("server_identity_hash".to_owned(), Value::Null);
    item.insert("source_label".to_owned(), Value::Null);
    item.insert(
        "state".to_owned(),
        grant.get("state").cloned().unwrap_or(Value::Null),
    );
    item.insert("stale".to_owned(), Value::from(false));
    item.insert(
        "grant_revision".to_owned(),
        grant.get("revision").cloned().unwrap_or(Value::Null),
    );
    item
}

/// The catalog's tool declarations by name; a declaration without a text
/// name describes nothing a command can be matched to.
fn tools_by_name(payload: &Value) -> HashMap<&str, &Value> {
    let mut by_name = HashMap::new();
    let Some(tools) = payload.get("tools").and_then(Value::as_array) else {
        return by_name;
    };
    for tool in tools {
        if !tool.is_object() {
            continue;
        }
        if let Some(name) = tool.get("name").and_then(Value::as_str) {
            by_name.insert(name, tool);
        }
    }
    by_name
}

fn table_exists(connection: &Connection, table: &str) -> StoreResult<bool> {
    let row = query_one(
        connection,
        "select 1 as present from sqlite_master where type = 'table' and name = ?",
        &[Value::from(table)],
    )?;
    Ok(row.is_some())
}

fn column_names(connection: &Connection, table: &str) -> StoreResult<BTreeSet<String>> {
    let rows = query_all(
        connection,
        "select name from pragma_table_info(?)",
        &[Value::from(table)],
    )?;
    Ok(rows
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}
