"""Find every Python site that produces a Guard verdict from Python control flow.

MAJ-AC-01 asks whether any entry root still authorizes an operation on a verdict
Python computed. Reachability and line counts cannot answer that, so this walks
the package's syntax tree instead and reports each function that turns Python
control flow into one of the enforced ``GuardAction`` strings.

It reports three shapes:

``return "allow"``
    a function whose own branching settles on a verdict;
``decision = "allow"``
    an assignment to a name the runtime reads as the enforced verdict;
``f(policy_action="allow")``
    a call that passes one as the verdict argument.

Finding a site is not itself a defect. Decoding a signed remote answer, filing
the user's approval-gate pick, rendering the resident's reply and failing closed
when the resident cannot be reached all land here, and all of them are allowed.
What the invariant forbids is Python *composing* a verdict the resident did not
give. Each known site therefore carries its audited reading in
``docs/guard/audits/python-verdict-sites.json``; this script compares what it
finds against that baseline so a new site has to be audited before it lands.

Run it from the repository root::

    python3 scripts/audit_python_verdict_sites.py            # list what is there
    python3 scripts/audit_python_verdict_sites.py --check    # fail on drift
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "src" / "codex_plugin_scanner"
BASELINE = REPO_ROOT / "docs" / "guard" / "audits" / "python-verdict-sites.json"

# ``GuardAction`` in src/codex_plugin_scanner/guard/models.py.
ACTIONS = frozenset(
    {"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"}
)
# Names the runtime reads as the enforced verdict, rather than as a label, a
# display bucket or a test fixture.
VERDICT_NAMES = frozenset(
    {
        "action",
        "action_floor",
        "decision",
        "effect",
        "floor",
        "guard_action",
        "policy_action",
        "policy_decision",
        "resolved_action",
        "verdict",
    }
)


def _action(node: ast.expr | None) -> str | None:
    """The ``GuardAction`` string this expression is, or ``None``."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in ACTIONS:
        return node.value
    return None


def _target_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _hits(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, object]]:
    """Every verdict this function's body produces from its own control flow."""

    found: list[dict[str, object]] = []
    for node in ast.walk(func):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not func:
            # A nested function is reported under its own name.
            continue
        if isinstance(node, ast.Return):
            action = _action(node.value)
            if action is not None:
                found.append({"line": node.lineno, "kind": "return", "value": action})
        elif isinstance(node, ast.Assign):
            action = _action(node.value)
            if action is not None and any(
                _target_name(target) in VERDICT_NAMES for target in node.targets
            ):
                found.append({"line": node.lineno, "kind": "assign", "value": action})
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                action = _action(keyword.value)
                if action is not None and keyword.arg in VERDICT_NAMES:
                    found.append(
                        {
                            "line": node.lineno,
                            "kind": f"keyword:{keyword.arg}",
                            "value": action,
                        }
                    )
    return sorted(found, key=lambda hit: (hit["line"], hit["kind"]))


def discover(package: Path = PACKAGE) -> list[dict[str, object]]:
    """Every verdict-producing function in the package, in a stable order."""

    sites: list[dict[str, object]] = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            hits = _hits(node)
            if hits:
                sites.append(
                    {
                        "file": path.relative_to(REPO_ROOT).as_posix(),
                        "func": node.name,
                        "line": node.lineno,
                        "hits": hits,
                    }
                )
    return sites


def _baseline_keys() -> set[tuple[str, str]]:
    audited = json.loads(BASELINE.read_text(encoding="utf-8"))
    return {(str(site["file"]), str(site["func"])) for site in audited["sites"]}


def _check() -> int:
    found = {(str(site["file"]), str(site["func"])) for site in discover()}
    audited = _baseline_keys()
    added = sorted(found - audited)
    removed = sorted(audited - found)
    for file, func in added:
        print(
            f"{file}: {func} produces a Guard verdict and is not in the authority audit.\n"
            f"  Read docs/guard/audits/maj-ac-01-per-root-authority-audit.md, decide whether it\n"
            f"  renders the resident's verdict or composes one, then record it in {BASELINE.name}.",
            file=sys.stderr,
        )
    for file, func in removed:
        print(
            f"{file}: {func} is in the authority audit but no longer produces a verdict. "
            f"Drop its row from {BASELINE.name}.",
            file=sys.stderr,
        )
    if added or removed:
        return 1
    print(f"authority audit: {len(found)} verdict sites, all audited")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when the package no longer matches the audited baseline",
    )
    args = parser.parse_args(argv)
    if args.check:
        return _check()
    print(json.dumps(discover(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
