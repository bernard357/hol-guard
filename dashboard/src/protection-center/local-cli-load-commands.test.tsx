import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { DiscoveryFailure } from "../discovery-failure";
import { LocalCliApiError, normalizeLocalCliItem } from "../local-cli-api";
import { LocalCliLoadCommands, loadCommandsFailureMessage } from "./local-cli-load-commands";

const raw = {
  cli_id: "local-cli.lanectl-abcdef12",
  name: "lanectl",
  kind: "executable",
  identity_hash: "a".repeat(64),
  example_label: "lanectl",
  interpreter_name: null,
  observed_count: 2,
  last_seen_at: "2026-10-17T00:00:00Z",
  surface: "cli",
  state: "allowed",
  stale: false,
  grant_revision: 1,
  authority_revision: 1,
  suggestable: false,
  commands: [],
};
const render = (value: Record<string, unknown>, disabled = false) => renderToStaticMarkup(createElement(LocalCliLoadCommands, {
  item: normalizeLocalCliItem(value), disabled, onLoaded: async () => undefined,
}));

// A program offers one action and says what Guard will run before it runs it.
const empty = render(raw);
assert.match(empty, />Load commands</);
assert.match(empty, /lanectl --help/);
assert.match(empty, /empty temporary folder/);
assert.match(empty, /load commands only for tools you trust/);
assert.match(empty, /never changes a choice you already made/);
assert.doesNotMatch(empty, /role="alert"/);

// With commands already listed, the action checks for new ones.
const listed = render({ ...raw, commands: [{ command_id: "deploy", name: "deploy", usage: "lanectl deploy", description: "", state: "allow" }] });
assert.match(listed, />Check for new commands</);

// The action follows the panel's busy state.
assert.match(render(raw, true), /<button[^>]*disabled=""/);

// A script is never offered a load: Guard points to the full-path flow instead.
const script = render({ ...raw, kind: "script" });
assert.doesNotMatch(script, /<button/);
assert.match(script, /Guard does not run scripts on its own/);
assert.match(script, /Add custom extension using its full path/);

// Shared job failures that name connectors get tool wording; others pass through.
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("catalog_limit_reached", "connector text")), /lists more commands than Guard can keep/);
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("discovery_failed", "connector text")), /Loading stopped/);
assert.equal(loadCommandsFailureMessage(new DiscoveryFailure("cli_help_unreadable", "help text")), "help text");
assert.equal(loadCommandsFailureMessage(new LocalCliApiError("cli_identity_changed", "not the program Guard recorded")), "not the program Guard recorded");
assert.match(loadCommandsFailureMessage(new TypeError("Failed to fetch")), /Try again/);
