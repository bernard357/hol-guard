"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

for (const [name, version, reason] of [
  ["unrecognized version", "1.4.1", "Review the backport"],
  ["modified source", "1.4.0", "Refuse a different or modified Forge source"],
]) {
  test("reject " + name + " without emitting VEX", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-forge-check-"));
    try {
      const packageRoot = path.join(root, "node_modules", "node-forge");
      fs.mkdirSync(path.join(packageRoot, "lib"), { recursive: true });
      fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ version }));
      const rsa = path.join(packageRoot, "lib", "rsa.js");
      fs.writeFileSync(rsa, "unrecognized RSA implementation");
      const script = path.join(root, "harden-forge.cjs");
      fs.copyFileSync(path.join(__dirname, "harden-forge.cjs"), script);
      const vex = path.join(root, "proof.json");
      const result = spawnSync(process.execPath, [script, "--vex-output", vex], { encoding: "utf8" });
      assert.notEqual(result.status, 0);
      assert(result.stderr.includes(reason));
      assert.equal(fs.existsSync(vex), false);
      assert.equal(fs.readFileSync(rsa, "utf8"), "unrecognized RSA implementation");
    } finally {
      fs.rmSync(root, { recursive: true });
    }
  });
}

// The zod assessment is only worth attesting while the tree it describes still
// looks the way it was read. Each refusal below is one of those readings.
const { verifyClassicZodEntry } = require("./harden-forge.cjs");

function zodRoot(version, { branded = false, importer = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-zod-check-"));
  const packageRoot = path.join(root, "node_modules", "zod");
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ version, main: "index.js" }));
  const schema = branded ? "{ _zod: { def: {} } }" : "{}";
  fs.writeFileSync(
    path.join(packageRoot, "index.js"),
    `exports.string = () => (${schema});\nexports.array = () => (${schema});\n`,
  );
  if (importer) {
    const dependency = path.join(root, "node_modules", "@scope", "dependency");
    fs.mkdirSync(dependency, { recursive: true });
    fs.writeFileSync(path.join(dependency, "index.mjs"), importer);
  }
  return root;
}

test("attest the locked zod only while its package root stays classic", () => {
  const root = zodRoot("3.25.76");
  try {
    assert.equal(verifyClassicZodEntry(root), "3.25.76");
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

for (const [name, root, reason] of [
  ["the locked version moves", () => zodRoot("4.6.6"), "Review the zod assessment when the locked version changes."],
  [
    "the package root builds v4 schemas",
    () => zodRoot("3.25.76", { branded: true }),
    "Refuse to attest: the zod package root now builds v4 schemas.",
  ],
  [
    "a dependency names the v4 core",
    () => zodRoot("3.25.76", { importer: 'import { $ZodArray } from "zod/v4/core";\n' }),
    "Refuse to attest: a locked dependency names the zod v4 core directly.",
  ],
]) {
  test("refuse to attest zod once " + name, () => {
    const built = root();
    try {
      // A predicate, not a built regex: the reason is prose and escaping it by hand
      // is both unnecessary and easy to get wrong.
      assert.throws(
        () => verifyClassicZodEntry(built),
        (thrown) => thrown instanceof Error && thrown.message.includes(reason),
      );
    } finally {
      fs.rmSync(built, { recursive: true });
    }
  });
}

// Hardening Forge for a validate or publish run writes no VEX statement, so a
// zod assessment that has gone stale must not fail those runs.
test("harden Forge without the zod assessment when no VEX is written", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mcpb-forge-only-"));
  try {
    const modules = path.join(root, "node_modules");
    fs.cpSync(path.join(__dirname, "node_modules", "node-forge"), path.join(modules, "node-forge"), {
      recursive: true,
    });
    // A zod the assessment no longer describes.
    const zod = path.join(modules, "zod");
    fs.mkdirSync(zod, { recursive: true });
    fs.writeFileSync(path.join(zod, "package.json"), JSON.stringify({ version: "4.6.6", main: "index.js" }));
    fs.writeFileSync(path.join(zod, "index.js"), "exports.string = () => ({});\nexports.array = () => ({});\n");
    for (const name of ["harden-forge.cjs", "harden-zod.cjs", "verify-forge.cjs"]) {
      fs.copyFileSync(path.join(__dirname, name), path.join(root, name));
    }
    const script = path.join(root, "harden-forge.cjs");

    const hardened = spawnSync(process.execPath, [script], { encoding: "utf8" });
    assert.equal(hardened.status, 0, hardened.stderr);
    assert(hardened.stdout.includes("Verified MCPB Forge backport SHA-256: "));

    const vex = path.join(root, "proof.json");
    const attested = spawnSync(process.execPath, [script, "--vex-output", vex], { encoding: "utf8" });
    assert.notEqual(attested.status, 0);
    assert(attested.stderr.includes("Review the zod assessment when the locked version changes."));
    assert.equal(fs.existsSync(vex), false);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
