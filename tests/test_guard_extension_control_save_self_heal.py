"""A failed extension policy save must never leave later saves refused."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.daemon import extension_control_api as extension_control_api_module
from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_proof import ExtensionControlProof
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore

from .guard_extension_control_authority_fixtures import (
    MemorySecretStore,
    _allow_local_terminal_confirmation,  # noqa: F401
    _commit,
    _store,
)
from .test_guard_extension_control_api import _mutation_payload

_CATALOG = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest


def _view(health: AuthorityHealth, revision: int = 4) -> ExtensionControlAuthorityView:
    return ExtensionControlAuthorityView(health, revision, _CATALOG, ())


def _transition_count(store: GuardStore) -> int:
    with store._connect() as connection:
        return int(connection.execute("select count(*) from extension_control_authority_transition").fetchone()[0])


def test_a_save_whose_anchor_write_fails_leaves_nothing_to_recover(tmp_path: Path) -> None:
    secrets = MemorySecretStore()
    store = _store(tmp_path, secrets)
    secrets.fail_anchor_set_number = secrets.anchor_set_count + 1
    with pytest.raises(ExtensionControlAuthorityError, match="anchor"):
        _commit(store)

    # The failed save took its own prepared row back, so the authority is
    # protected at once, without waiting out the retry window, and the very
    # next save commits.
    assert _transition_count(store) == 0
    view = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY, read_only=True)
    assert view.health is AuthorityHealth.PROTECTED
    _commit(store, key="change-2")
    assert store.read_extension_control_authority(catalog_digest=_CATALOG).revision == 1


class _SharedReadCannotHealStore:
    """Authority whose shared read still sees a prepared row only a writer can roll back."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.reads: list[bool] = []

    def read_extension_control_authority_for_registry(
        self, _registry: object, *, read_only: bool = False, **_kwargs: object
    ) -> ExtensionControlAuthorityView:
        self.reads.append(read_only)
        return _view(AuthorityHealth.RECOVERY_REQUIRED if read_only else AuthorityHealth.PROTECTED)


def test_preview_heals_authority_a_failed_save_left_behind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(extension_control_api_module, "prepare_candidate", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        extension_control_api_module,
        "issue_extension_control_proof",
        lambda *_args, **_kwargs: cast(ExtensionControlProof, SimpleNamespace(proof_id="proof-1")),
    )
    store = _SharedReadCannotHealStore(tmp_path / "guard-home")
    runtime = ExtensionControlRuntime(_view(AuthorityHealth.RECOVERY_REQUIRED))
    service = ExtensionControlApiService(
        store=cast(GuardStore, store), registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY, runtime=runtime
    )

    preview = service.preview({**_mutation_payload(), "session_nonce": "session-1", "approval_password": "pw"})

    assert preview["proof_id"] == "proof-1"
    assert runtime.current().health is AuthorityHealth.PROTECTED
    assert store.reads[:2] == [True, False]


def test_daemon_refresh_reads_as_the_writer_when_a_shared_read_needs_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    protected = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    runtime = ExtensionControlRuntime(_view(AuthorityHealth.RECOVERY_REQUIRED, protected.revision))
    server = cast(
        _GuardDaemonHttpServer,
        cast(
            object,
            SimpleNamespace(
                store=store,
                extension_control_runtime=runtime,
                extension_control_api=SimpleNamespace(catalog_digest=_CATALOG),
                _installed_authority_pending=False,
                _extension_control_on_core_registry=False,
            ),
        ),
    )
    reads: list[bool] = []

    def read(_registry: object, *, read_only: bool = False, **_kwargs: object) -> ExtensionControlAuthorityView:
        reads.append(read_only)
        return _view(AuthorityHealth.RECOVERY_REQUIRED, protected.revision) if read_only else protected

    monkeypatch.setattr(store, "read_extension_control_authority_for_registry", read)

    snapshot = _GuardDaemonHttpServer.refresh_extension_control_runtime(server)

    assert reads == [True, False]
    assert snapshot.health is AuthorityHealth.PROTECTED
    assert runtime.current().health is AuthorityHealth.PROTECTED
