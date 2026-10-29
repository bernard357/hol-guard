"""An approved Cloud exception lifts the Cloud policy block it was approved against."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_exceptions import (
    cloud_exception_from_mapping,
    cloud_exception_lifting_policy_bundle_decision,
    list_active_cloud_exceptions,
)
from codex_plugin_scanner.guard.consumer.native_decision_projection import (
    _ConsumerAuthorityInputs,
    _native_runtime_decision,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.cloud_exception_bundle_fixtures import (
    build_cloud_exception_bundle_entry,
    build_cloud_exception_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring
from tests.policy_store_support import replace_remote_policies

WORKSPACE_ID = "workspace-sync-proof"
ARTIFACT_ID = "codex:project:sync-proof"
NOW = "2026-10-29T12:00:00+00:00"
PACKAGE_ARTIFACT_ID = "codex:project:package-request:left-pad"
BUNDLE_BLOCK = {"action": "block", "source": "policy-bundle", "scope": "artifact", "artifact_id": ARTIFACT_ID}


def _lifting(
    exceptions: list[dict[str, object]],
    decision: dict[str, object] | None = None,
    *,
    harness: str = "codex",
    artifact_id: str | None = ARTIFACT_ID,
    publisher: str | None = None,
    workspace: str | None = None,
    now: str = NOW,
) -> str | None:
    return cloud_exception_lifting_policy_bundle_decision(
        {"cloudExceptions": exceptions},
        BUNDLE_BLOCK if decision is None else decision,
        harness=harness,
        artifact_id=artifact_id,
        publisher=publisher,
        workspace=workspace,
        now=now,
    )


def test_active_artifact_exception_lifts_the_cloud_block() -> None:
    entry = build_cloud_exception_bundle_entry()
    assert _lifting([entry]) == entry["exceptionId"]


def test_exception_lifts_only_cloud_policy_decisions() -> None:
    entry = build_cloud_exception_bundle_entry()
    assert _lifting([entry], {**BUNDLE_BLOCK, "source": "local"}) is None
    assert _lifting([entry], {**BUNDLE_BLOCK, "action": "allow"}) is None


def test_expired_exception_lifts_nothing() -> None:
    entry = build_cloud_exception_bundle_entry(expires_at="2026-10-29T11:59:59+00:00")
    assert _lifting([entry]) is None


@pytest.mark.parametrize(
    ("overrides", "lookup"),
    [
        ({}, {"artifact_id": "codex:project:other"}),
        ({}, {"harness": "claude-code"}),
        ({"workingDirectory": "/repo/a"}, {"workspace": "/repo/b"}),
        ({"publisher": "acme"}, {"publisher": "other"}),
    ],
)
def test_exception_lifts_nothing_outside_its_targets(overrides: dict[str, object], lookup: dict[str, str]) -> None:
    entry = {**build_cloud_exception_bundle_entry(), **overrides}
    lifted = _lifting(
        [entry],
        harness=lookup.get("harness", "codex"),
        artifact_id=lookup.get("artifact_id", ARTIFACT_ID),
        publisher=lookup.get("publisher"),
        workspace=lookup.get("workspace"),
    )
    assert lifted is None


def test_artifact_exception_without_an_artifact_lifts_nothing() -> None:
    entry = build_cloud_exception_bundle_entry(exception_id="exception-1")
    del entry["artifactId"]
    assert _lifting([entry]) is None


def test_exception_without_a_harness_applies_to_every_harness() -> None:
    entry = build_cloud_exception_bundle_entry()
    del entry["harness"]
    assert _lifting([entry], harness="claude-code") == entry["exceptionId"]
    parsed = cloud_exception_from_mapping(entry, provenance="policy-bundle")
    assert parsed is not None
    assert list_active_cloud_exceptions([parsed], harness="claude-code", now=NOW) == [parsed]


def test_publisher_exception_lifts_the_publisher_artifacts() -> None:
    entry = {
        **build_cloud_exception_bundle_entry(exception_id="exception-publisher"),
        "scope": "publisher",
        "publisher": "acme",
    }
    del entry["artifactId"]
    assert _lifting([entry], publisher="acme") == "exception-publisher"
    assert _lifting([entry], publisher=None) is None


def _store_with_bundle(tmp_path: Path, cloud_exceptions: list[dict[str, object]]) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": WORKSPACE_ID}, NOW)
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE_ID), NOW)
    store.set_sync_payload(
        "policy_bundle",
        build_cloud_exception_policy_bundle(cloud_exceptions=cloud_exceptions, workspace_id=WORKSPACE_ID),
        NOW,
    )
    replace_remote_policies(
        store,
        [
            PolicyDecision(
                harness="codex",
                scope="harness",
                action="block",
                artifact_id="family:package-request",
                source="policy-bundle",
                owner="pkg-block",
                reason="Block risky package installs before execution.",
            )
        ],
        NOW,
        remote_write_authorized=True,
    )
    return store


def _saved_decision_sent_to_composer(store: GuardStore) -> object:
    sent: dict[str, object] = {}

    def composer(operation: str, payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        assert operation == "runtime_authoritative"
        runtime = payload["runtime"]
        assert isinstance(runtime, dict)
        sent["saved_decision"] = runtime["saved_decision"]
        return {"append_pending_claim": False}

    inputs = _ConsumerAuthorityInputs(
        store=store,
        harness="codex",
        workspace=None,
        now=NOW,
        trusted_request_overrides={},
        claimed_saved_approval_overrides={},
        retained_saved_approval_overrides={},
        saved_approval_qualification_overrides={},
        runtime_detector_composition=None,
        runtime_detector_block_reason=None,
        runtime_signals=[],
        pending_approval_claims=None,
    )
    _ = _native_runtime_decision(
        inputs,
        artifact_id=PACKAGE_ARTIFACT_ID,
        approval_context_hash="sha256:artifact",
        publisher=None,
        memory_command=None,
        memory_artifact_type=None,
        memory_artifact_name=None,
        current_action="warn",
        configured_action=None,
        scanner_action="allow",
        raw_scoring_recommendation="allow",
        skill_directory_identity_reusable=None,
        composer=composer,
    )
    return sent["saved_decision"]


def test_evaluation_drops_the_cloud_block_an_approved_exception_lifts(tmp_path: Path) -> None:
    store = _store_with_bundle(
        tmp_path,
        [{**build_cloud_exception_bundle_entry(), "artifactId": PACKAGE_ARTIFACT_ID}],
    )

    assert _saved_decision_sent_to_composer(store) is None


def test_evaluation_keeps_the_cloud_block_once_the_exception_is_gone(tmp_path: Path) -> None:
    store = _store_with_bundle(
        tmp_path,
        [
            {
                **build_cloud_exception_bundle_entry(expires_at="2026-10-29T11:00:00+00:00"),
                "artifactId": PACKAGE_ARTIFACT_ID,
            }
        ],
    )

    saved = _saved_decision_sent_to_composer(store)
    assert isinstance(saved, dict)
    assert saved["action"] == "block"
