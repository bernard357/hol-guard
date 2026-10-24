"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const lockedZodVersion = "3.25.76";
const issueBudget = 32;
const parsers = {
  "v3/types.js": {
    sha256: "9763a2938f0e7f983363ef4bf6530e7583e3f2d54f8a4a6684efad58febc6e8e",
    invalidToken: "INVALID",
    mergeArray: "ParseStatus.mergeArray",
  },
  "v3/types.cjs": {
    sha256: "06487cc05ed45c5dd29789bf0aa75734d1ce06592a7f2665ba4ca90a68e8a3e1",
    invalidToken: "parseUtil_js_1.INVALID",
    mergeArray: "parseUtil_js_1.ParseStatus.mergeArray",
  },
};

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

const exactFrom = `message: def.exactLength.message,
                });
                status.dirty();
            }
        }
        if (def.minLength !== null) {`;

const maxFrom = `message: def.maxLength.message,
                });
                status.dirty();
            }
        }
        if (ctx.common.async) {`;

const setFrom = `message: def.maxSize.message,
                });
                status.dirty();
            }
        }
        const valueType = this._def.valueType;`;

const setWalkFrom = `        const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
        if (ctx.common.async) {
            return Promise.all(elements).then((elements) => finalizeSet(elements));
        }
        else {
            return finalizeSet(elements);
        }`;

const setWalkTo = `        const values = [...ctx.data.values()];
        if (ctx.common.async) {
            const elements = [];
            const step = (index) => {
                if (index >= values.length || ctx.common.issues.length >= ${issueBudget}) return finalizeSet(elements);
                return Promise.resolve(valueType._parse(new ParseInputLazyPath(ctx, values[index], ctx.path, index))).then((element) => {
                    elements.push(element);
                    return step(index + 1);
                });
            };
            return Promise.resolve(step(0));
        }
        const elements = [];
        for (let index = 0; index < values.length; index++) {
            if (ctx.common.issues.length >= ${issueBudget}) break;
            elements.push(valueType._parse(new ParseInputLazyPath(ctx, values[index], ctx.path, index)));
        }
        return finalizeSet(elements);`;

function exactTo(invalidToken) {
  return `message: def.exactLength.message,
                });
                if (tooBig) return ${invalidToken};
                status.dirty();
            }
        }
        if (def.minLength !== null) {`;
}

function maxTo(invalidToken) {
  return `message: def.maxLength.message,
                });
                return ${invalidToken};
            }
        }
        if (ctx.common.async) {`;
}

function setTo(invalidToken) {
  return `message: def.maxSize.message,
                });
                return ${invalidToken};
            }
        }
        const valueType = this._def.valueType;`;
}

function arrayFrom(mergeArray) {
  return `        if (ctx.common.async) {
            return Promise.all([...ctx.data].map((item, i) => {
                return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
            })).then((result) => {
                return ${mergeArray}(status, result);
            });
        }
        const result = [...ctx.data].map((item, i) => {
            return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
        });
        return ${mergeArray}(status, result);`;
}

function arrayTo(invalidToken, mergeArray) {
  return `        if (ctx.common.async) {
            const items = [...ctx.data];
            const parsed = [];
            const step = (index) => {
                if (index >= items.length) return ${mergeArray}(status, parsed);
                if (ctx.common.issues.length >= ${issueBudget}) return ${invalidToken};
                return def.type._parseAsync(new ParseInputLazyPath(ctx, items[index], ctx.path, index)).then((parsedItem) => {
                    parsed.push(parsedItem);
                    return step(index + 1);
                });
            };
            return Promise.resolve(step(0));
        }
        const items = [...ctx.data];
        const result = [];
        for (let index = 0; index < items.length; index++) {
            if (ctx.common.issues.length >= ${issueBudget}) return ${invalidToken};
            result.push(def.type._parseSync(new ParseInputLazyPath(ctx, items[index], ctx.path, index)));
        }
        return ${mergeArray}(status, result);`;
}

function replacements(parser) {
  return [
    [exactFrom, exactTo(parser.invalidToken)],
    [maxFrom, maxTo(parser.invalidToken)],
    [setFrom, setTo(parser.invalidToken)],
    [arrayFrom(parser.mergeArray), arrayTo(parser.invalidToken, parser.mergeArray)],
    [setWalkFrom, setWalkTo],
  ];
}

function restoreOriginal(text, pairs) {
  const alreadyPatched = pairs.every(([, next]) => text.includes(next));
  if (!alreadyPatched) return text;
  let restored = text;
  for (let index = pairs.length - 1; index >= 0; index -= 1) {
    const [previous, next] = pairs[index];
    const parts = restored.split(next);
    assert.equal(parts.length, 2, "Refuse a partial zod parser patch.");
    restored = parts.join(previous);
  }
  return restored;
}

function applyPairs(text, pairs) {
  let patched = text;
  for (const [previous, next] of pairs) {
    const parts = patched.split(previous);
    assert.equal(parts.length, 2, "Refuse a zod parser that does not contain the expected check.");
    patched = parts.join(next);
  }
  return patched;
}

function hardenZod(root = __dirname) {
  const packageRoot = path.join(root, "node_modules", "zod");
  const metadata = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  assert.equal(metadata.version, lockedZodVersion, "Review the zod parser patch when the locked version changes.");
  const digests = {};
  for (const [relativePath, parser] of Object.entries(parsers)) {
    const target = path.join(packageRoot, relativePath);
    const pairs = replacements(parser);
    const original = restoreOriginal(fs.readFileSync(target, "utf8"), pairs);
    assert.equal(sha256(original), parser.sha256, "Refuse a different or modified zod parser.");
    const patched = applyPairs(original, pairs);
    if (fs.readFileSync(target, "utf8") !== patched) fs.writeFileSync(target, patched);
    digests[relativePath] = sha256(patched);
  }
  return digests;
}

/// Restores the locked zod parser in `root`, so a tree that was already
/// hardened can be exercised from its unpatched state. The restored text must
/// match the pinned digest; anything else is refused rather than overwritten.
function restoreZod(root = __dirname) {
  const packageRoot = path.join(root, "node_modules", "zod");
  for (const [relativePath, parser] of Object.entries(parsers)) {
    const target = path.join(packageRoot, relativePath);
    const original = restoreOriginal(fs.readFileSync(target, "utf8"), replacements(parser));
    assert.equal(sha256(original), parser.sha256, `Refuse a different or modified zod parser: ${relativePath}.`);
    fs.writeFileSync(target, original);
  }
}

// Attests the digest of a parser this run can reconstruct: the pinned locked
// text with exactly this file's replacements applied. A marker line alone
// would attest any file that happens to contain it.
function patchedParserSha256(root = __dirname) {
  const packageRoot = path.join(root, "node_modules", "zod");
  const digests = {};
  for (const [relativePath, parser] of Object.entries(parsers)) {
    const current = fs.readFileSync(path.join(packageRoot, relativePath), "utf8");
    const pairs = replacements(parser);
    const original = restoreOriginal(current, pairs);
    assert.equal(sha256(original), parser.sha256, `Refuse to attest: ${relativePath} is not the locked zod parser.`);
    assert.equal(
      current,
      applyPairs(original, pairs),
      `Refuse to attest: the zod v3 parser ${relativePath} is not patched.`,
    );
    digests[relativePath] = sha256(current);
  }
  return digests["v3/types.js"];
}

if (require.main === module) {
  const args = process.argv.slice(2);
  assert(args.length <= 1, "Invalid zod hardening arguments.");
  const digests = hardenZod(args[0] ? path.resolve(args[0]) : __dirname);
  console.log("Verified zod v3 parser patch SHA-256: " + digests["v3/types.js"]);
}

module.exports = hardenZod;
module.exports.patchedParserSha256 = patchedParserSha256;
module.exports.restoreZod = restoreZod;
module.exports.issueBudget = issueBudget;
