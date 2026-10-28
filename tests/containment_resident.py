"""Answer containment routing from the compiled resident in tests that patch the host.

Many routing tests patch ``sys.platform`` to replay another host's sink, and
point ``guard_home`` at a scratch directory with no enrolled resident. This
fixture keeps the routing answer the resident's own: every containment query
is sent to the session's resident, on the real platform, carrying the host the
test chose. Only the platform the transport runs on and the home it asks are
redirected; the routing table and the rewrite are never re-implemented.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_containment_route as route_module


@pytest.fixture
def containment_resident(monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path) -> Path:
    """Route every containment question through the session resident; returns its home."""

    home = native_approval_reuse_runtime
    real_platform = sys.platform
    real_ask = route_module._ask

    def ask(
        kind: str,
        inputs: Mapping[str, object],
        guard_home: Path | None,
        validate: Any,
        deadline: float | None,
        feature: str = route_module.HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE,
    ) -> dict[str, Any]:
        # The inputs already name the host the test chose; only the transport
        # runs on the real platform, against the session's resident.
        del guard_home, deadline
        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", real_platform)
            return real_ask(kind, inputs, home, validate, None, feature)

    monkeypatch.setattr(route_module, "_ask", ask)
    return home
