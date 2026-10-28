import assert from "node:assert/strict";

import type { PackageShimEntry } from "./guard-types";
import { rosterGroupFor } from "./supply-chain-firewall-controls";
import { managerRowNote, shadowingCommand } from "./supply-chain-firewall-manager-row";

function shim(overrides: Partial<PackageShimEntry>): PackageShimEntry {
  return {
    active: false,
    activation_state: "uninstalled",
    detected: true,
    installed: false,
    integrity: "ok",
    last_intercept_proof_at: null,
    manager: "npm",
    path_broken: false,
    path_index: null,
    path_summary: null,
    real_binary_found: true,
    real_binary_path: null,
    real_binary_path_index: null,
    shim_path: null,
    tested: false,
    ...overrides,
  };
}

// Groups: detected but not installed waits below; installed and working is done;
// anything installed but not intercepting needs a fix.
assert.equal(rosterGroupFor(undefined), "unprotected");
assert.equal(rosterGroupFor(shim({})), "unprotected");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "protected" })), "protected");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "repair_required", path_broken: true })), "fix");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "restart_required" })), "fix");

// The row names the command that runs first, with home shortened, never the shim folder.
assert.equal(
  shadowingCommand("/Users/alex/Library/pnpm/npm precedes /Users/alex/.hol-guard/package-shims/bin/npm"),
  "~/Library/pnpm/npm",
);
assert.equal(shadowingCommand("/opt/homebrew/bin/pip precedes /tmp/guard/package-shims/bin/pip"), "/opt/homebrew/bin/pip");
assert.equal(shadowingCommand("something else"), null);
assert.equal(shadowingCommand(null), null);

assert.equal(
  managerRowNote(
    shim({
      installed: true,
      activation_state: "repair_required",
      path_broken: true,
      path_summary: "/home/alex/.local/bin/uv precedes /home/alex/.hol-guard/package-shims/bin/uv",
    }),
  ),
  "Your shell runs ~/.local/bin/uv first, so installs skip Guard.",
);
assert.equal(
  managerRowNote(shim({ installed: true, activation_state: "repair_required", path_broken: true })),
  "Another copy runs first, so installs skip Guard.",
);
assert.equal(managerRowNote(shim({ installed: true, activation_state: "restart_required" })), "Open a new shell to turn this on.");
assert.equal(managerRowNote(shim({ installed: true, activation_state: "repair_required" })), "Guard's shim folder is not on PATH yet.");
assert.equal(managerRowNote(shim({ installed: true, activation_state: "protected" })), null);
assert.equal(managerRowNote(shim({})), null);

console.log("supply-chain-roster-groups.test.ts: all assertions passed");
