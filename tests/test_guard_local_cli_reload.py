from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import local_cli_api
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity, recognize_operator_cli
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fixture tool is a POSIX shell script")

SEEN_AT = "2026-10-27T12:00:00Z"


def _command(command_id: str) -> LocalCliCommand:
    return LocalCliCommand(command_id=command_id, name=command_id, usage=command_id, description="")


@pytest.fixture
def tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> UnlistedCliIdentity:
    home = tmp_path / "operator"
    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True)
    program = bin_dir / "fixturetool"
    program.write_text("#!/bin/sh\necho 'Usage: fixturetool <command>'\n", encoding="utf-8")
    program.chmod(program.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    identity, code, _ = recognize_operator_cli("fixturetool", cwd=home, home_dir=home)
    assert identity is not None, code
    return identity


@dataclass
class Probes:
    calls: list[str] = field(default_factory=list)
    commands: tuple[LocalCliCommand, ...] = (LocalCliCommand("deploy", "deploy", "deploy", ""),)
    status: str = "ok"
    during: Callable[[], None] | None = None


@pytest.fixture
def probes(monkeypatch: pytest.MonkeyPatch) -> Probes:
    recorded = Probes()

    def discover(command, identity, cwd, home_dir, guard_home):
        recorded.calls.append(command)
        if recorded.during is not None:
            recorded.during()
        return recorded.commands, recorded.status, "/resolved/path/never/stored"

    monkeypatch.setattr(local_cli_api, "_discover_from_command", discover)
    return recorded


def _service(tmp_path: Path, identity: UnlistedCliIdentity) -> tuple[GuardStore, LocalCliApiService]:
    store = GuardStore(tmp_path / "guard")
    store.record_local_cli_observation(identity, seen_at=SEEN_AT, source_path="user-tool", surface="cli")
    return store, LocalCliApiService(store=store)


def _finished(service: LocalCliApiService, job: dict[str, object]) -> dict[str, object]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = service._discovery_jobs.read(str(job["job_id"]))
        if result["state"] not in {"running", "cancelling"}:
            return result
        time.sleep(0.01)
    pytest.fail("loading commands did not finish promptly")


def _item(store: GuardStore, cli_id: str) -> dict[str, object]:
    return next(item for item in store.list_local_cli_items() if item.get("cli_id") == cli_id)


def test_loading_commands_adds_new_ones_and_keeps_existing_choices(tmp_path, tool, probes):
    store, service = _service(tmp_path, tool)
    store.replace_local_cli_commands(tool.cli_id, (_command("legacy"),))
    store.upsert_local_cli_command_states(tool.cli_id, {"legacy": "block"})
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True})
        assert _finished(service, job)["state"] == "complete"
    finally:
        assert service.close_discovery()
    assert probes.calls == ["fixturetool"]
    catalog = {command.command_id for command in store.read_local_cli_command_catalog(tool.cli_id)}
    assert {"legacy", "deploy"} <= catalog
    assert store.read_local_cli_command_states(tool.cli_id).get("legacy") == "block"
    item = _item(store, tool.cli_id)
    assert item["help_status"] == "ok"
    assert item["source_path"] == "user-tool"


def test_unreadable_help_changes_nothing(tmp_path, tool, probes):
    store, service = _service(tmp_path, tool)
    store.replace_local_cli_commands(tool.cli_id, (_command("legacy"),))
    probes.commands, probes.status = (), "failed"
    before = store.read_local_cli_command_catalog(tool.cli_id)
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True})
        result = _finished(service, job)
    finally:
        assert service.close_discovery()
    assert (result["state"], result["error"]) == ("failed", "cli_help_unreadable")
    assert store.read_local_cli_command_catalog(tool.cli_id) == before


def test_loading_needs_consent_before_anything_runs(tmp_path, tool, probes):
    _, service = _service(tmp_path, tool)
    try:
        with pytest.raises(LocalCliApiError) as raised:
            service.refresh_job({"cli_id": tool.cli_id})
    finally:
        assert service.close_discovery()
    assert raised.value.code == "discovery_process_consent_required"
    assert probes.calls == []


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("deploy.sh", "executable"),
        ("release.py", "executable"),
        ("fixturetool", "script"),
        ("-fixturetool", "executable"),
    ],
)
def test_scripts_are_never_run_on_their_own(tmp_path, tool, probes, name, kind):
    stored = UnlistedCliIdentity(f"local-cli.stored-{len(name)}-{kind}", name, kind, "e" * 64, name, None)
    store, service = _service(tmp_path, stored)
    try:
        with pytest.raises(LocalCliApiError) as raised:
            service.refresh_job({"cli_id": stored.cli_id, "confirm_process_start": True})
    finally:
        assert service.close_discovery()
    assert (raised.value.status, raised.value.code) == (400, "cli_reload_needs_path")
    assert probes.calls == []
    assert store.read_local_cli_command_catalog(stored.cli_id) == []


def test_a_replaced_program_is_not_run(tmp_path, tool, probes):
    recorded = UnlistedCliIdentity(tool.cli_id, tool.name, "executable", "d" * 64, tool.example_label, None)
    _, service = _service(tmp_path, recorded)
    try:
        with pytest.raises(LocalCliApiError) as raised:
            service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True})
    finally:
        assert service.close_discovery()
    assert (raised.value.status, raised.value.code) == (409, "cli_identity_changed")
    assert probes.calls == []


def test_a_full_catalog_reports_the_limit(tmp_path, tool, probes):
    _, service = _service(tmp_path, tool)
    probes.commands = tuple(_command(f"c{index}") for index in range(120))
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True})
        result = _finished(service, job)
    finally:
        assert service.close_discovery()
    assert (result["state"], result["error"]) == ("failed", "catalog_limit_reached")


def test_a_real_probe_only_ever_asks_for_help(tmp_path, monkeypatch):
    home = tmp_path / "operator"
    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True)
    acted = tmp_path / "acted"
    program = bin_dir / "fixturetool"
    program.write_text(
        "#!/bin/sh\n"
        'for arg in "$@"; do [ "$arg" = --help ] && helped=1; done\n'
        f'[ -n "$helped" ] || {{ touch "{acted}"; exit 0; }}\n'
        "printf 'Usage: fixturetool <command>\\n\\nCommands:\\n  deploy  Ship it\\n  status  Show state\\n'\n",
        encoding="utf-8",
    )
    program.chmod(program.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    identity, code, _ = recognize_operator_cli("fixturetool", cwd=home, home_dir=home)
    assert identity is not None, code
    store, service = _service(tmp_path, identity)
    try:
        job = service.refresh_job({"cli_id": identity.cli_id, "confirm_process_start": True})
        assert _finished(service, job)["state"] == "complete"
    finally:
        assert service.close_discovery()
    assert not acted.exists()
    catalog = {command.command_id for command in store.read_local_cli_command_catalog(identity.cli_id)}
    assert {"deploy", "status"} <= catalog


def test_a_tool_found_again_during_loading_keeps_its_new_catalog(tmp_path, tool, probes):
    store, service = _service(tmp_path, tool)
    replacement = replace(tool, identity_hash="f" * 64)
    probes.during = lambda: store.record_local_cli_observation(replacement, seen_at=SEEN_AT, surface="cli")
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True})
        result = _finished(service, job)
    finally:
        assert service.close_discovery()
    assert (result["state"], result["error"]) == ("failed", "cli_identity_changed")
    assert store.read_local_cli_command_catalog(tool.cli_id) == []


def test_a_cancel_before_writing_stores_nothing(tmp_path, tool, probes):
    store, service = _service(tmp_path, tool)
    jobs: list[str] = []
    probes.during = lambda: service._discovery_jobs.read(jobs[0], cancel=True)
    job_id = "a" * 32
    jobs.append(job_id)
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True, "client_job_id": job_id})
        assert _finished(service, job)["state"] == "cancelled"
    finally:
        assert service.close_discovery()
    assert store.read_local_cli_command_catalog(tool.cli_id) == []


def test_a_cancel_after_writing_began_reports_the_stored_result(tmp_path, tool, probes, monkeypatch):
    store, service = _service(tmp_path, tool)
    job_id = "b" * 32
    merge = store.merge_local_cli_commands
    cancelled: list[dict[str, object]] = []

    def merge_then_cancel(*args, **kwargs):
        cancelled.append(service._discovery_jobs.read(job_id, cancel=True))
        return merge(*args, **kwargs)

    monkeypatch.setattr(store, "merge_local_cli_commands", merge_then_cancel)
    try:
        job = service.refresh_job({"cli_id": tool.cli_id, "confirm_process_start": True, "client_job_id": job_id})
        assert _finished(service, job)["state"] == "complete"
    finally:
        assert service.close_discovery()
    assert cancelled[0]["state"] == "running"
    assert "deploy" in {command.command_id for command in store.read_local_cli_command_catalog(tool.cli_id)}


def test_discovery_never_runs_a_program_whose_identity_changed(tool, monkeypatch):
    ran: list[object] = []
    monkeypatch.setattr(local_cli_api, "discover_local_cli_commands", lambda *args, **kwargs: ran.append(args))
    stale = replace(tool, identity_hash="c" * 64)
    home = Path(os.environ["HOME"])
    _, status, _ = local_cli_api._discover_from_command(tool.name, stale, home, home, home / "guard")
    assert status == "failed"
    assert ran == []
