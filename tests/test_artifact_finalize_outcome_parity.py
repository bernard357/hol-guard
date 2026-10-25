"""The resident answers the recorded browser outcomes.

The recorder froze the browser-outcome section of the retired
``finalize_native_artifact_hook``. This suite asks the resident for each
recorded outcome and checks it answers as recorded.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from tests.artifact_finalize_support import load_vectors


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_resident_answers_the_recorded_browser_outcomes() -> None:
    failures: list[str] = []
    for vector in load_vectors()["browser"]:
        answer = finalize.native_artifact_browser_outcome(vector["facts"])
        failures.extend(
            f"{vector['facts']}: {key} {answer[key]!r} != {value!r}"
            for key, value in vector["answer"].items()
            if answer[key] != value
        )
    assert failures == []
