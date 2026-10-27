# MAJ-AC-01: per-root authority audit

Audited at `c2d1754375` (2026-10-27). Reproduce with
`python3 scripts/audit_python_verdict_sites.py`.

MAJ-AC-01 asks for something the migration report does not measure. The report
counts reachability and lines of Python; the acceptance criterion is about
authority: does any entry root still authorize an operation on a verdict Python
computed? A module can be large and reachable and hold no authority at all, and
a four-line helper can hold all of it. Counting either way answers the wrong
question.

This audit answers it directly. `scripts/audit_python_verdict_sites.py` walks
the package's syntax tree and reports every function that turns Python control
flow into one of the six enforced `GuardAction` strings — a `return "allow"`, an
assignment to a name the runtime reads as the verdict, or a call that passes one
as the verdict argument. That set is small enough to read by hand, and it is
exhaustive in a way a grep is not.

## What it found

Thirty-five functions across twenty-six files, every one of them under
`src/codex_plugin_scanner/guard/`. Nothing outside the guard package produces a
verdict, so the console-script entry points (`hol-guard`, `hol-guard-eval`,
`hol-guard-secrets` and the `plugin-*` aliases) hold no authority of their own.

Nineteen of the thirty-five can only ever produce a `block`, a `review` or a
`require-reapproval`. A Python-produced verdict that is stricter than the
resident's cannot authorize anything, and fail-closed behaviour when the
resident is unreachable is the design, so these were cleared as a class rather
than read one at a time. They are the fail-closed renderers, the review queues
and the protect-path blocks.

The remaining sixteen can produce an `allow`, so each one was read. Fifteen
hold no authority of their own:

- **Renders the resident's verdict** — `native_local_cli_grant_response` acts
  only on the resident's `hook_local_cli_rule` answer and leaves the review
  standing when it cannot read one; `_tool_decision_after_runtime_allow` carries
  the native route's own `decision_policy_action`; `allow_tool_call` files the
  row for a call the route already allowed; `local_tool_grant_decision` refuses
  any reply that is not a resident allow; `_expected_policy_action` echoes the
  action the request carried.
- **Decodes a signed or stored decision** — `_exact_action`,
  `normalize_remote_approval_decision` and `_normalize_action` map a signed
  one-time answer onto the enforced vocabulary. `local_cli_command_state` admits
  or rejects a configured value and chooses nothing.
- **Records what the user answered** — `resolve_interactive_decisions` and
  `_prompt_for_artifact` prompt only for artifacts the resident already marked
  for review and file the pick behind the approval gate;
  `native_saved_decision_response` replays a saved exact-action decision bound to
  the artifact hash, and only where the resident marked the review approvable;
  `temporary_mcp_grant_decision` and `_continuation` do the same for MCP grants
  and retry copy; `wait_for_grok_live_approval` reads resolved approval rows.
- **Neither** — `_repair_command_activity_persistence_health` writes a probe row
  inside a savepoint and rolls it back, proving the evidence write path without
  evaluating policy.

## The finding

`src/codex_plugin_scanner/guard/daemon/hook_native_package_review.py` settles a
package review in Python in one case the resident did not settle.

Its main path is clean: the resident plans the review (`package_review_plan`),
says whether a verdict may let the command continue at all (`may_allow`), and
evaluates the request artifact (`evaluate_package_request_artifact`, which is a
thin call onto `evaluate_package_request_native`). An `allow` verdict renders an
allow and a `block` renders a block.

`_script_free_watch` is the exception:

```python
def _script_free_watch(evaluation: PackageRequestEvaluation) -> bool:
    """Whether every package is watched only because no package code runs."""
    return (
        evaluation.decision == "monitor"
        and bool(evaluation.packages)
        and all(package.get("scriptFreeRegistryInstall") is True for package in evaluation.packages)
    )
```

The resident said `monitor`. Python reads the per-package
`scriptFreeRegistryInstall` flags and decides that a watch which holds only
because no package code runs may continue as an allow. Every fact in that
decision comes from Rust —
`supply_chain_package_eval/fallback_packages.rs` sets the flag, and it sets it
only where `script_free_registry_install` or `script_free_git_free_tree_install`
proved the install writes registry package files and nothing else — but the rule
that combines them into an allow exists nowhere else. `rg
script_free_watch rust/crates` finds nothing.

This is a residual authority-composition rule, not an open door: the install it
admits is one the resident already proved runs no package code, and `may_allow`
still gates it. It is nonetheless the shape MAJ-AC-01 was written to catch, and
it is the only one left.

**Fix:** have the evaluation carry the answer. The resident already computes
every input, so the widening belongs beside them in
`supply_chain_package_eval`, surfaced as a field on the evaluation result that
`native_package_review_response` reads the way it reads `decision`. Tracked
separately so this audit can land on its own.

## Keeping it true

A point-in-time audit stops being evidence the moment someone adds a site.
`docs/guard/audits/python-verdict-sites.json` records the reading for each of
the thirty-five, and `scripts/audit_python_verdict_sites.py --check` fails when
the package and the baseline disagree —
`tests/test_python_verdict_site_audit.py` runs it. A new verdict site has to be
read and recorded before it can land, which is what MAJ-AC-01 asked for in the
first place.
