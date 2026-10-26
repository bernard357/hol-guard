"""Review floor for skills, MCP servers and plugins with a low HOL Registry trust score.

Python holds the registry lookup because it is network IO with an on-disk
cache. Every judgement around it belongs to the resident: whether the artifact
qualifies for a score at all, what the ``low_trust_artifact`` risk class
resolves to, whether the score is below the threshold, and the signal that
explains the floor.

The lookup is costly, so the resident asks for it rather than being handed it.
A first query carries no score; only when the floor would otherwise apply does
the answer come back with ``score_required``, and the score is then read and
sent in a second query. A configured, settled or unscored artifact, or an
allowed risk class, is answered without touching the network, exactly as the
Python resolution short-circuited.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..config import GuardConfig, risk_action_config_facts
from ..models import GuardArtifact
from ..native_consumer_artifact_compose import NativeConsumerComposeError, native_consumer_compose
from ..registry_trust import registry_trust_score
from ..runtime.signals import RiskSignalV2


@dataclass(frozen=True, slots=True)
class LowTrustFloor:
    action: str
    score: int
    signal: RiskSignalV2


def low_trust_floor(
    guard_home: Path | None,
    config: GuardConfig,
    *,
    harness: str,
    artifact: GuardArtifact,
    configured_action: str | None,
    fresh_decision: bool,
) -> LowTrustFloor | None:
    """Return the review floor for a low-trust artifact, or ``None``.

    Only an unconfigured artifact that is first seen or changed is scored: a
    configured override or an unchanged, already decided artifact keeps its
    decision, and a saved Always allow still applies after the floor raises the
    action.
    """

    facts: dict[str, object] = {
        "risk_action_config": risk_action_config_facts(config),
        "harness": harness if isinstance(harness, str) else None,
        "artifact_type": artifact.artifact_type,
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "configured_action": configured_action,
        "fresh_decision": bool(fresh_decision),
        "trust_score": None,
    }
    answer = _compose(facts, guard_home)
    if answer is not None and answer["score_required"]:
        score = registry_trust_score(guard_home, artifact_type=artifact.artifact_type, name=artifact.name)
        # No score is no answer, and never a review.
        answer = None if score is None else _compose({**facts, "trust_score": score}, guard_home)
    floor = None if answer is None else answer["floor"]
    return None if floor is None else _decode(cast(Mapping[str, object], floor))


def _compose(facts: Mapping[str, object], guard_home: Path | None) -> dict[str, object] | None:
    """The resident's answer, or ``None`` when it could not be reached.

    The floor only ever strengthens an action, and the evaluation that reads it
    composes its current action through the same resident a moment later, so an
    unreachable runtime fails the artifact closed there rather than here.
    """

    try:
        return native_consumer_compose("low_trust_floor", facts, guard_home=guard_home)
    except NativeConsumerComposeError:
        return None


def _decode(floor: Mapping[str, object]) -> LowTrustFloor | None:
    action, score, signal = floor.get("action"), floor.get("score"), floor.get("signal")
    if not isinstance(action, str) or not isinstance(score, int) or isinstance(score, bool):
        return None
    if not isinstance(signal, Mapping):
        return None
    try:
        decoded = RiskSignalV2.from_dict(signal)
    except (TypeError, ValueError):
        return None
    return LowTrustFloor(action=action, score=score, signal=decoded)


__all__ = ["LowTrustFloor", "low_trust_floor"]
