import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { DiscoveryFailure } from "../discovery-failure";
import { LocalCliApiError, normalizeLocalCliItem } from "../local-cli-api";
import {
  LocalCliLoadCommands,
  PATH_ENTRY_CODES,
  loadCommandsFailureMessage,
  loadCommandsNeedsPath,
} from "./local-cli-load-commands";

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

// Guard's own root and other entries are not listed commands.
const synthetic = render({ ...raw, commands: ["root", "other"].map((id) => ({ command_id: id, name: id, usage: id, description: "", state: "inherit" })) });
assert.match(synthetic, />Load commands</);

// The action follows the panel's busy state.
assert.match(render(raw, true), /<button[^>]*disabled=""/);

// A script loads from the full path the operator enters, on the extension page itself.
for (const scriptLike of [{ ...raw, kind: "script" }, { ...raw, name: "approve-merge.sh" }, { ...raw, name: "release.PY" }]) {
  const script = render(scriptLike);
  assert.match(script, /Guard does not record where/);
  assert.match(script, />Full path to /);
  assert.match(script, /<input[^>]*placeholder="\/path\/to\//);
  assert.match(script, /only if it is the one Guard recorded/);
  assert.match(script, /load commands only for scripts you trust/);
  // With no path entered yet there is nothing to run.
  assert.match(script, /<button[^>]*disabled=""[^>]*>Load commands</);
  assert.doesNotMatch(script, /Add custom extension/);
}
assert.equal(loadCommandsNeedsPath({ kind: "executable", name: "lanectl" }), false);
assert.equal(loadCommandsNeedsPath({ kind: "executable", name: "pr-approve-merge.sh" }), true);
assert.equal(loadCommandsNeedsPath({ kind: "executable", name: "-lanectl" }), true);
assert.equal(loadCommandsNeedsPath({ kind: "script", name: "lanectl" }), true);
assert.doesNotMatch(empty, /Full path to/);

// Shared job failures that name connectors get tool wording; others pass through.
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("catalog_limit_reached", "connector text")), /lists more commands than Guard can keep/);
assert.match(loadCommandsFailureMessage(new DiscoveryFailure("discovery_failed", "connector text")), /Loading stopped/);
assert.equal(loadCommandsFailureMessage(new DiscoveryFailure("cli_help_unreadable", "help text")), "help text");
assert.equal(loadCommandsFailureMessage(new LocalCliApiError("cli_identity_changed", "not the program Guard recorded")), "not the program Guard recorded");
assert.match(loadCommandsFailureMessage(new TypeError("Failed to fetch")), /Try again/);

// Every failure of the daemon's own PATH lookup offers the full path next: it
// can miss the tool, or find another program of that name. The daemon checks
// the identity of whatever the path resolves to before it probes anything.
for (const code of ["cli_not_on_guard_path", "cli_identity_changed", "cli_reload_needs_path"]) {
  assert.ok(PATH_ENTRY_CODES.has(code), code);
}
// A path the operator mistyped, or a tool that is really gone, is not one.
for (const code of ["cli_path_invalid", "cli_path_not_found", "cli_help_unreadable"]) {
  assert.ok(!PATH_ENTRY_CODES.has(code), code);
}
