"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const test = require("node:test");

const { issueBudget, patchedParserSha256, restoreZod } = require("./harden-zod.cjs");

function copyZod(root) {
  const source = path.join(__dirname, "node_modules", "zod");
  assert.equal(fs.existsSync(source), true, "npm ci --ignore-scripts --prefix .github/tools/mcpb-cli first");
  fs.cpSync(source, path.join(root, "node_modules", "zod"), { recursive: true });
  // The source tree may already be hardened, because the MCPB CLI patches it
  // in place. Every test here starts from the locked parser.
  restoreZod(root);
}

function run(root) {
  return spawnSync(process.execPath, [path.join(__dirname, "harden-zod.cjs"), root], { encoding: "utf8" });
}

function checkParser(entry, kind) {
  const probe = `
    const assert = require("node:assert/strict");
    const budget = ${issueBudget};
    async function main() {
      const loaded = ${kind === "esm"
        ? `await import(${JSON.stringify(pathToFileURL(entry).href)})`
        : `require(${JSON.stringify(entry)})`};
      const z = loaded.z;
      const valid = z.array(z.string()).safeParse(["a", "b", "c"]);
      assert.equal(valid.success, true);
      assert.deepEqual(valid.data, ["a", "b", "c"]);

      let exact = 0;
      const exactResult = z.array(z.string().refine(() => { exact += 1; return true; })).length(2).safeParse(["a", "b", "c"]);
      assert.equal(exactResult.success, false);
      assert.equal(exact, 0);
      assert.equal(exactResult.error.issues[0].code, "too_big");

      let bounded = 0;
      const boundedResult = z.array(z.string().refine(() => { bounded += 1; return true; })).max(2).safeParse(["a", "b", "c", "d"]);
      assert.equal(boundedResult.success, false);
      assert.equal(bounded, 0);
      assert.equal(boundedResult.error.issues.length, 1);
      assert.equal(boundedResult.error.issues[0].code, "too_big");

      let seen = 0;
      const failing = z.array(z.string().refine(() => { seen += 1; return false; })).safeParse(Array.from({ length: budget * 4 }, () => "x"));
      assert.equal(failing.success, false);
      assert.equal(seen, budget);
      assert.equal(failing.error.issues.length, budget);

      let asyncSeen = 0;
      const asyncFailing = await z.array(z.string().refine(async () => { asyncSeen += 1; return false; })).safeParseAsync(Array.from({ length: budget * 4 }, () => "x"));
      assert.equal(asyncFailing.success, false);
      assert.equal(asyncSeen, budget);
      assert.equal(asyncFailing.error.issues.length, budget);
    }
    main().then(() => {}, (error) => { console.error(error); process.exit(1); });
  `;
  const result = spawnSync(process.execPath, ["-e", probe], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test("patch the locked zod v3 parsers and stop a failing collection", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zod-parser-patch-"));
  try {
    copyZod(root);
    assert.throws(
      () => patchedParserSha256(root),
      (error) => error instanceof Error && error.message.includes("is not patched"),
    );
    const first = run(root);
    assert.equal(first.status, 0, first.stderr);
    const patchedSha = patchedParserSha256(root);
    assert.match(first.stdout, new RegExp(patchedSha));
    const packageRoot = path.join(root, "node_modules", "zod");
    checkParser(path.join(packageRoot, "index.cjs"), "cjs");
    checkParser(path.join(packageRoot, "index.js"), "esm");
    const second = run(root);
    assert.equal(second.status, 0, second.stderr);
    assert.equal(patchedParserSha256(root), patchedSha);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});

test("refuse a zod parser whose source hash changed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zod-parser-mismatch-"));
  try {
    copyZod(root);
    const target = path.join(root, "node_modules", "zod", "v3", "types.js");
    fs.writeFileSync(target, fs.readFileSync(target, "utf8") + "\n");
    const result = run(root);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Refuse a different or modified zod parser/);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
