"""Daemon routes for reviewed workspace dependency fixes: auth, CSRF, limits, flow."""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_runner as runner
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import (
    _dashboard_token_for,
    _dashboard_token_with_claims,
    _read_json_response,
    _request,
)
from tests.workspace_fix_support import (
    COMPLETE_SUPPLY_CHAIN,
    FINDING_ID,
    FIXED_MANIFEST,
    KEYS,
    MANIFEST,
    assess,
    digest,
    seeded_store,
    write_manifest,
)

PATH = "/v1/supply-chain/workspace-fix-proposals"
BODY = {"codebase_key": KEYS.codebase_key, "worktree_key": KEYS.worktree_key, "finding_id": FINDING_ID}


@pytest.fixture
def native_binary() -> None:
    if not Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "").is_file():
        pytest.skip("needs HOL_GUARD_NATIVE_BINARY for the compiled runtime")


@contextmanager
def _daemon(tmp_path: Path) -> Iterator[tuple[GuardDaemonServer, GuardStore, Path, str]]:
    root = tmp_path / "work"
    manifest = write_manifest(root)
    store = seeded_store(tmp_path, root)
    assess(store, snapshot="before", at=runner.now_ms() - 60_000)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        yield daemon, store, manifest, _dashboard_token_for(store)
    finally:
        daemon.stop()


def _raw(port: int, token: str, *, length: int, origin: str | None = None) -> bytes:
    lines = [f"POST {PATH} HTTP/1.1", "Host: 127.0.0.1", f"X-Guard-Token: {token}", f"Content-Length: {length}"]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        client.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        client.shutdown(socket.SHUT_WR)
        return client.recv(4096)
    finally:
        client.close()


def test_routes_refuse_anonymous_foreign_origin_scoped_and_oversized_requests(
    tmp_path: Path, native_binary: None
) -> None:
    with _daemon(tmp_path) as (daemon, store, manifest, token):
        before = manifest.read_bytes()
        proposal_path = f"{PATH}/{'a' * 32}/apply"
        anonymous = [
            _read_json_response(_request(daemon.port, PATH, method="GET"))[0],
            _read_json_response(_request(daemon.port, PATH, payload=BODY))[0],
            _read_json_response(_request(daemon.port, proposal_path))[0],
        ]
        forbidden = [
            _read_json_response(_request(daemon.port, PATH, payload=BODY, token=token, origin="https://evil.example")),
            _read_json_response(_request(daemon.port, proposal_path, token=token, origin="https://evil.example")),
            _read_json_response(_request(daemon.port, PATH, method="GET", token=token, origin="https://evil.example")),
        ]
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        scoped = _dashboard_token_with_claims(
            auth_token,
            {"surface": "command-action", "action_path": "command_activity_read", "allowed_read_paths": [PATH]},
        )
        scoped_status = _read_json_response(_request(daemon.port, PATH, payload=BODY, token=scoped))[0]
        oversized = _raw(daemon.port, auth_token, length=1_000_001, origin="http://127.0.0.1:6174")
        assert manifest.read_bytes() == before
        assert assessments.latest_assessed_run(store, KEYS) is not None

    assert all(status in {401, 403} for status in anonymous)
    assert [(status, body.get("error")) for status, body in forbidden] == [(403, "forbidden_origin")] * 3
    assert scoped_status in {401, 403}
    assert oversized.split(b"\r\n", 1)[0].split()[1] == b"413"


def test_malformed_requests_are_rejected_before_any_work(tmp_path: Path, native_binary: None) -> None:
    with _daemon(tmp_path) as (daemon, _store, manifest, token):
        before = manifest.read_bytes()
        bad_keys = _read_json_response(_request(daemon.port, PATH, token=token, payload={"finding_id": FINDING_ID}))
        bad_finding = _read_json_response(_request(daemon.port, PATH, token=token, payload={**BODY, "finding_id": "x"}))
        bad_id = _read_json_response(_request(daemon.port, f"{PATH}/not-hex!/apply", token=token))
        missing = _read_json_response(_request(daemon.port, f"{PATH}/{'a' * 32}/apply", token=token))
        no_keys = _read_json_response(_request(daemon.port, PATH, method="GET", token=token))
        assert manifest.read_bytes() == before
    assert bad_keys == (400, {"error": "invalid_worktree"})
    assert bad_finding == (400, {"error": "invalid_finding_id"})
    assert bad_id == (400, {"error": "invalid_proposal_id"})
    assert missing == (404, {"error": "fix_proposal_not_found"})
    assert no_keys == (400, {"error": "invalid_worktree"})


def test_prepare_apply_and_verify_over_the_daemon(tmp_path: Path, native_binary: None) -> None:
    with _daemon(tmp_path) as (daemon, store, manifest, token):
        status, prepared = _read_json_response(_request(daemon.port, PATH, token=token, payload=BODY))
        assert status == 201
        [proposal] = prepared["proposals"]
        assert proposal["state"] == "prepared" and proposal["diff"]
        assert manifest.read_bytes() == MANIFEST.replace("\n", "\r\n").encode(), "prepare must not write"

        status, applied = _read_json_response(
            _request(daemon.port, f"{PATH}/{proposal['proposal_id']}/apply", token=token)
        )
        assert status == 200
        assert applied["lockfile_update_required"] is True and applied["lockfiles"] == []
        assert applied["proposal"]["state"] == "applied"
        assert manifest.read_bytes() == FIXED_MANIFEST.replace("\n", "\r\n").encode()

        claimed = assessments.claim_next(store, owner="verify", now_ms=runner.now_ms() + 1_000)
        assert claimed is not None and claimed.trigger_kind == "fix_verification"
        assert claimed.run_id == applied["verification_run_id"]
        assert assessments.finish(
            store,
            claimed,
            assessments.RunOutcome(
                state="partial", snapshot_digest=digest("after"), coverage=COMPLETE_SUPPLY_CHAIN, findings=[]
            ),
            now_ms=runner.now_ms() + 2_000,
        )
        query = f"?codebase_key={KEYS.codebase_key}&worktree_key={KEYS.worktree_key}&limit=500"
        status, listing = _read_json_response(_request(daemon.port, PATH + query, method="GET", token=token))
        again = _read_json_response(_request(daemon.port, f"{PATH}/{proposal['proposal_id']}/apply", token=token))

    assert status == 200
    assert [(item["proposal_id"], item["state"]) for item in listing["proposals"]] == [
        (proposal["proposal_id"], "verified_fixed")
    ]
    assert again == (409, {"error": "fix_proposal_not_prepared", "state": "verified_fixed"})


def test_stale_apply_over_the_daemon_is_a_409_and_leaves_the_file_alone(tmp_path: Path, native_binary: None) -> None:
    with _daemon(tmp_path) as (daemon, _store, manifest, token):
        _, prepared = _read_json_response(_request(daemon.port, PATH, token=token, payload=BODY))
        [proposal] = prepared["proposals"]
        edited = manifest.read_bytes() + b"\n"
        manifest.write_bytes(edited)
        status, body = _read_json_response(
            _request(daemon.port, f"{PATH}/{proposal['proposal_id']}/apply", token=token)
        )
        assert manifest.read_bytes() == edited
    assert (status, body) == (409, {"error": "fix_proposal_stale"})


def test_unsupported_findings_return_a_reason_over_the_daemon(tmp_path: Path, native_binary: None) -> None:
    with _daemon(tmp_path) as (daemon, store, _manifest, token):
        other = "e" * 32
        assess(
            store,
            snapshot="again",
            at=runner.now_ms() - 30_000,
            findings=[
                {
                    "finding_id": other,
                    "source_kind": "supply_chain",
                    "ecosystem": "npm",
                    "package_name": "left-pad",
                    "fix_version": "1.3.0",
                }
            ],
        )
        status, body = _read_json_response(
            _request(daemon.port, PATH, token=token, payload={**BODY, "finding_id": other})
        )
    assert (status, body["error"], body["reason"]) == (422, "fix_unsupported", "transitive_dependency")
    assert json.dumps(body).count(str(tmp_path)) == 0, "responses carry no local paths"
