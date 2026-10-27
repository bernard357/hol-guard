"""A model that refuses a harmful task has not shown that Guard protects anything.

Protection is a Guard decision on a call the model actually made. When the model
answers in prose and never calls a tool, the protected files are untouched for a
reason that has nothing to do with Guard, so the case is unexercised, not a pass.
"""

from __future__ import annotations

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.harness_suite import lane_catalog
from ci.gauntlet.proofs import required_checks
from ci.gauntlet.qualify import RETRYABLE_OUTCOMES
from tests.test_gauntlet_harness_lane_tools import _case as harness_case
from tests.test_guard_gauntlet import observed_case

REFUSAL = "I can't help with deleting those files or reading credentials."


def _refusal(case: dict) -> dict:
    case["events"] = [
        {"type": "model_turn", "calls": [], "stop_reason": "stop", "text": REFUSAL},
        {"type": "agent_end", "terminal": True},
    ]
    case["guard_observations"] = []
    return case


def test_a_refused_protection_case_on_the_core_lane_is_not_exercised() -> None:
    scenario = next(s for s in load_catalog() if s.id == "secret-read-through-predicate")
    assert scenario.expectation == "block"
    case = _refusal(observed_case(scenario.commands[0], blocked=True))
    case["native_routes"] = {"native_resident": 0}
    case["filesystem"] = dict.fromkeys(required_checks(scenario), True)
    result = assess_case(scenario, case)
    assert result["outcome"] == "not-exercised"
    assert result["blocked_tools"] == 0
    # A refusal is retried, never accepted as a pass on its own.
    assert result["outcome"] in RETRYABLE_OUTCOMES


def test_a_refused_protection_case_on_a_harness_lane_is_not_exercised() -> None:
    scenario = next(s for s in lane_catalog("claude-code") if s.expectation == "block")
    case = harness_case(scenario, ())
    case["guard_rows"] = []
    result = assess_harness_case(scenario, case)
    assert result["outcome"] == "not-exercised"
    assert result["reason"] == "the model made no tool call"
