"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const originalSha256 = "fd4740238145ec26470eb3f06a627c72039538ce1307dbdce40521f94dfd0a50";
const originalCondition = "            obj.value.length !== 2) {";
const fixedCondition = `            obj.value.length !== 2 ||
            obj.value[0].value.length < 1 || obj.value[0].value.length > 2 ||
            (obj.value[0].value.length === 2 &&
              (obj.value[0].value[1].tagClass !== asn1.Class.UNIVERSAL ||
                obj.value[0].value[1].type !== asn1.Type.NULL ||
                obj.value[0].value[1].constructed ||
                obj.value[0].value[1].value !== ''))) {`;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

const lockedZodVersion = "3.25.76";
const zodAdvisory = "CVE-2023-54404";

// The advisory covers every zod below 4.6.6, which sweeps in the locked 3.25
// line because 3.25 ships the zod 4 core beside the classic one. The issue
// accumulation it describes lives in `handleArrayResult` under
// `zod/v4/core/schemas`, and the package root still resolves to the classic v3
// surface, so nothing reaches that core without importing `zod/v4` by name.
// Refuse to attest any of that unless it still holds for the locked tree.
function verifyClassicZodEntry(root = __dirname) {
  const packageRoot = path.join(root, "node_modules", "zod");
  const metadata = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  assert.equal(metadata.version, lockedZodVersion, "Review the zod assessment when the locked version changes.");
  const zod = require(packageRoot);
  // The v4 core brands every schema it builds; the classic surface does not.
  assert.equal(zod.array(zod.string())._zod, undefined, "Refuse to attest: the zod package root now builds v4 schemas.");
  const reaching = [...reachesZodCore(path.join(root, "node_modules"), path.join(root, "node_modules", "zod"))];
  assert.deepEqual(reaching, [], "Refuse to attest: a locked dependency names the zod v4 core directly.");
  return metadata.version;
}

// Every file a dependency could import the core from, by name. A match in a
// comment only makes this refuse to attest, which is the safe direction.
function* reachesZodCore(directory, zodRoot) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (candidate !== zodRoot) yield* reachesZodCore(candidate, zodRoot);
    } else if (entry.isFile() && /\.[cm]?[jt]s$/.test(entry.name)) {
      if (fs.readFileSync(candidate, "utf8").includes("zod/v4")) yield path.relative(zodRoot, candidate);
    }
  }
}

function hardenForge() {
  const packageRoot = path.join(__dirname, "node_modules", "node-forge");
  const packageMetadata = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  assert.equal(packageMetadata.version, "1.4.0", "Review the backport when the locked Forge version changes.");
  const target = path.join(packageRoot, "lib", "rsa.js");
  const current = fs.readFileSync(target, "utf8");
  const original = current.includes(fixedCondition) ? current.replace(fixedCondition, originalCondition) : current;
  assert.equal(sha256(original), originalSha256, "Refuse a different or modified Forge source file.");
  assert.equal(original.split(originalCondition).length, 2, "Expected exactly one RSA verification condition.");
  const patched = original.replace(originalCondition, fixedCondition);
  if (current !== patched) fs.writeFileSync(target, patched);
  assert.equal(sha256(fs.readFileSync(target)), sha256(patched));
  require("./verify-forge.cjs")();
  return sha256(patched);
}

if (require.main === module) {
  const args = process.argv.slice(2);
  assert(args.length === 0 || (args.length === 2 && args[0] === "--vex-output"), "Invalid hardening arguments.");
  const patchedSha256 = hardenForge();
  if (args.length) {
    // Only the VEX writer depends on the zod assessment. Hardening Forge for a
    // validate or publish run must not fail on an attestation it never writes.
    const verifiedZodVersion = verifyClassicZodEntry();
    const vex = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "https://github.com/hashgraph-online/hol-guard/blob/main/.github/tools/mcpb-cli/harden-forge.cjs",
      author: "HOL Guard maintainers",
      timestamp: "2026-10-02T00:00:00Z",
      version: 1,
      statements: [{
        vulnerability: { name: "CVE-2026-85393" },
        products: [{ "@id": "pkg:npm/node-forge@1.4.0" }],
        status: "fixed",
        impact_statement: `The locked MCPB build tool applies and tests a strict AlgorithmIdentifier backport before CLI use. Patched rsa.js SHA-256: ${patchedSha256}.`,
      }, {
        vulnerability: { name: zodAdvisory },
        products: [{ "@id": `pkg:npm/zod@${verifiedZodVersion}` }],
        status: "not_affected",
        justification: "vulnerable_code_not_in_execute_path",
        impact_statement: `The accumulation this advisory describes is in the zod 4 core, which ${verifiedZodVersion} ships beside the classic surface its package root exports. No locked dependency names \`zod/v4\`, and the root builds classic schemas, both checked before this statement is written.`,
      }],
    };
    fs.writeFileSync(args[1], JSON.stringify(vex, null, 2) + "\n");
  }
  console.log("Verified MCPB Forge backport SHA-256: " + patchedSha256);
}

module.exports = hardenForge;
module.exports.verifyClassicZodEntry = verifyClassicZodEntry;
