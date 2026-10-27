from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import pytest

from tests.developer_inspection_test_support import assert_leading_cd_inspection_allowed
from tests.git_execution_test_support import assert_host_git_proof_result
from tests.live_hook_review_support import LIVE_REVIEWS_RETIRED_ALLOW, live_shell_review, quietly_allowed
from tests.shell_wrapper_test_support import native_trusted_absolute_path


def _shell_path(path: Path) -> str:
    return shlex.quote(path.as_posix())


def _artifact(
    command: str,
    *,
    home: Path,
    harness: str = "pi",
    workspace: Path | None = None,
) -> dict[str, object] | None:
    """Return the live hook answer, or None when the command runs without review."""

    cwd = workspace if workspace is not None else home / "projects" / "current"
    cwd.mkdir(parents=True, exist_ok=True)
    result = live_shell_review(command, home_dir=home, cwd=cwd, harness=harness, tool_name="Bash")
    return None if quietly_allowed(result) else result


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_evaluate_compound_source_inspection_as_one_unit(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    artifact = _artifact(
        f'cd {_shell_path(workspace)} && fd -t f . | head -20 && echo "---MATCHES---" && rg -n TODO src | head -20',
        home=home,
        harness=harness,
    )

    assert_leading_cd_inspection_allowed(artifact)


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_recover_safe_inspection_after_cross_workspace_cd(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    (inspected_workspace / "src").mkdir(parents=True)

    artifact = _artifact(
        f"cd {_shell_path(inspected_workspace)} && grep -n TODO src/example.ts | head -20",
        home=home,
        harness=harness,
        workspace=active_workspace,
    )

    assert_leading_cd_inspection_allowed(artifact)


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_accept_safe_leading_delay_before_cross_workspace_inspection(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    artifact = _artifact(
        f"sleep 30 && cd {_shell_path(workspace)} && grep -n TODO src/example.ts | head -20",
        home=home,
        harness=harness,
    )

    assert_leading_cd_inspection_allowed(artifact)


@pytest.mark.parametrize(
    "delay_prefix",
    (
        "sleep 3601",
        "sleep 3600 && sleep 1",
        " && ".join(["sleep 1"] * 1100),
    ),
)
def test_compound_inspection_rejects_excessive_or_repeated_delays(live_hook_root: Path, delay_prefix: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    command = f"{delay_prefix} && cd {_shell_path(workspace)} && grep -n TODO src/example.ts | head -20"

    assert _artifact(command, home=home) is not None


@pytest.mark.parametrize("pattern", ("TODO", "component.property", "module-name.tsx"))
def test_compound_inspection_accepts_safe_stderr_suppression(live_hook_root: Path, pattern: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    command = f"cd {_shell_path(workspace)} && grep -rn {pattern} src 2>/dev/null | head -20"
    assert_leading_cd_inspection_allowed(_artifact(command, home=home))


@pytest.mark.parametrize("redirect", ("2>report.txt", "> report.txt", "< input.txt"))
def test_compound_inspection_keeps_file_redirection_guarded(live_hook_root: Path, redirect: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "src").mkdir(parents=True)

    assert _artifact(f"cd {_shell_path(workspace)} && grep -rn TODO src {redirect} | head -20", home=home) is not None


def test_cross_workspace_recovery_preserves_mutating_command_review(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    inspected_workspace.mkdir(parents=True)

    assert (
        _artifact(
            f"cd {_shell_path(inspected_workspace)} && git push origin main",
            home=home,
            workspace=active_workspace,
        )
        is not None
    )
    assert (
        _artifact(
            f"cd {_shell_path(inspected_workspace)} && vitest run src/example.test.ts --maxWorkers=1",
            home=home,
            workspace=active_workspace,
        )
        is not None
    )


@pytest.mark.parametrize("harness", ("omp", "pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_review_bounded_workspace_python_script_without_calling_it_destructive(
    live_hook_root: Path, harness: str
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "PelicanMarkdownWebsite" / "websiteToBuild"
    script = workspace / "scripts" / "wp_to_pelican.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('converted')\n", encoding="utf-8")

    result = live_shell_review(
        f"cd {_shell_path(workspace)} && python3 scripts/wp_to_pelican.py 2>&1",
        home_dir=home,
        cwd=workspace,
        harness=harness,
        tool_name="Bash",
    )

    # Contained or reviewed as a workspace script, never refused as destructive.
    assert result["reason_code"] in {
        "native_contained_execution_routed",
        "native_workspace_containment_required",
        "native_command_review_required",
    }


@pytest.mark.parametrize(
    "command",
    (
        "python3 -c \"from pathlib import Path; Path('data').unlink()\"",
        "python3 -m pip install unsafe-package",
        "python3 ../outside.py",
    ),
)
def test_python_escape_and_inline_mutation_still_require_review(live_hook_root: Path, command: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    (home / "outside.py").write_text("print('outside')\n", encoding="utf-8")

    assert _artifact(command, home=home, workspace=workspace) is not None


def _write_local_vitest(workspace: Path, *, with_lock: bool) -> None:
    (workspace / "node_modules" / ".bin").mkdir(parents=True)
    (workspace / "node_modules" / "vitest").mkdir()
    (workspace / "package.json").write_text(
        '{"devDependencies":{"vitest":"^4.1.8"}}\n',
        encoding="utf-8",
    )
    if with_lock:
        (workspace / "bun.lock").write_text(
            '{"lockfileVersion":1,"packages":{"vitest":["vitest@4.1.8"]}}\n',
            encoding="utf-8",
        )
    runner = workspace / "node_modules" / "vitest" / "vitest.mjs"
    runner.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner.chmod(0o755)
    (workspace / "node_modules" / "vitest" / "package.json").write_text(
        '{"name":"vitest","version":"4.1.8"}\n',
        encoding="utf-8",
    )
    (workspace / "node_modules" / ".bin" / "vitest").symlink_to("../vitest/vitest.mjs")


def test_declared_local_vitest_runner_requires_execution_review(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    test_workspace = home / "projects" / "tested"
    active_workspace.mkdir(parents=True)
    _write_local_vitest(test_workspace, with_lock=True)

    artifact = _artifact(
        f"cd {_shell_path(test_workspace)} && npx vitest run tests/example.test.tsx 2>&1 | tail -15",
        home=home,
        workspace=active_workspace,
    )

    assert artifact is not None
    assert artifact["policy_action"] != "allow"


def test_local_vitest_without_lock_evidence_still_requires_review(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    test_workspace = home / "projects" / "tested"
    active_workspace.mkdir(parents=True)
    _write_local_vitest(test_workspace, with_lock=False)

    artifact = _artifact(
        f"cd {_shell_path(test_workspace)} && npx vitest run tests/example.test.tsx",
        home=home,
        workspace=active_workspace,
    )

    assert artifact is not None


def test_local_vitest_runner_retargeted_to_another_package_requires_review(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    test_workspace = home / "projects" / "tested"
    active_workspace.mkdir(parents=True)
    _write_local_vitest(test_workspace, with_lock=True)
    unrelated_package = test_workspace / "node_modules" / "unrelated"
    unrelated_package.mkdir()
    payload = unrelated_package / "payload.mjs"
    payload.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    payload.chmod(0o755)
    runner = test_workspace / "node_modules" / ".bin" / "vitest"
    runner.unlink()
    runner.symlink_to("../unrelated/payload.mjs")

    artifact = _artifact(
        f"cd {_shell_path(test_workspace)} && npx vitest run tests/example.test.tsx",
        home=home,
        workspace=active_workspace,
    )

    assert artifact is not None


def test_local_vitest_package_symlinked_outside_node_modules_requires_review(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    test_workspace = home / "projects" / "tested"
    active_workspace.mkdir(parents=True)
    _write_local_vitest(test_workspace, with_lock=True)
    package_root = test_workspace / "node_modules" / "vitest"
    outside_package = home / "outside" / "vitest"
    outside_package.parent.mkdir()
    package_root.rename(outside_package)
    package_root.symlink_to(outside_package, target_is_directory=True)

    artifact = _artifact(
        f"cd {_shell_path(test_workspace)} && npx vitest run tests/example.test.tsx",
        home=home,
        workspace=active_workspace,
    )

    assert artifact is not None


@pytest.mark.parametrize(
    "runner_request",
    ("vitest@99.0.0", "vitest@file:./evil", "--package vitest@99.0.0 vitest"),
)
def test_local_runner_override_requests_still_require_review(live_hook_root: Path, runner_request: str) -> None:
    home = live_hook_root / "home"
    active_workspace = home / "projects" / "active"
    test_workspace = home / "projects" / "tested"
    active_workspace.mkdir(parents=True)
    _write_local_vitest(test_workspace, with_lock=True)
    (test_workspace / "evil").mkdir()

    artifact = _artifact(
        f"cd {_shell_path(test_workspace)} && npx {runner_request} run tests/example.test.tsx",
        home=home,
        workspace=active_workspace,
    )

    assert artifact is not None


def test_compound_git_and_filesystem_inspection_requires_host_binary_proof(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    artifact = _artifact(
        f'cd {_shell_path(workspace)} && git -C repository status --short && echo "---FILES---" && ls -la | head -20',
        home=home,
    )

    assert_host_git_proof_result(artifact is None, cwd=workspace)
    if os.name == "nt":
        assert artifact is not None
        assert artifact["policy_action"] != "allow"


@pytest.mark.xfail(
    os.name != "nt",
    reason="the live hook path reviews this shape; only the retired Python composition allowed it",
    strict=False,
)
def test_compound_stdin_only_python_observer_requires_host_binary_proof(live_hook_root: Path) -> None:
    # The resident applies the Windows host floor from its own build target,
    # so only a real Windows host reaches it; the Rust tests check the floor
    # itself on every platform.
    windows_host = os.name == "nt"
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    artifact = _artifact(
        f"cd {_shell_path(workspace)} && printf data | {_shell_path(Path(sys.executable))} "
        + '-c "import sys; print(sys.stdin.read().strip())"',
        home=home,
    )

    if windows_host:
        # The compound host recognizer has no Windows executable ACL proof.
        # A stdin-only script cannot waive the launch identity requirement.
        assert not native_trusted_absolute_path(Path(sys.executable), cwd=workspace, home_dir=home)
        assert artifact is not None
        # Whichever floor fires first, the launch is never allowed outright.
        assert artifact["policy_action"] != "allow"
    else:
        assert artifact is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_keep_compound_destructive_commands_guarded(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    workspace.mkdir(parents=True)

    artifact = _artifact(
        f"cd {_shell_path(workspace)} && printf ready && rm -rf ./generated-output",
        home=home,
        harness=harness,
    )

    assert artifact is not None
    assert artifact["policy_action"] == "block"


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_harnesses_keep_guard_removal_at_the_destructive_floor(
    live_hook_root: Path,
    harness: str,
) -> None:
    home = live_hook_root / "home"
    home.mkdir(exist_ok=True)

    artifact = _artifact("hol-guard uninstall --all", home=home, harness=harness)

    assert artifact is not None
    assert artifact["reason_code"] == "native_guard_self_protection"


def test_guard_removal_help_stays_non_destructive(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    home.mkdir(exist_ok=True)

    artifact = _artifact("hol-guard uninstall --help", home=home)

    assert artifact is None


def test_guard_name_inside_read_only_search_does_not_trigger_self_protection(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    skill = home / ".codex" / "plugins" / "github" / "SKILL.md"
    memory = home / ".codex" / "memories" / "MEMORY.md"
    skill.parent.mkdir(parents=True)
    memory.parent.mkdir(parents=True)
    skill.write_text("github skill\n", encoding="utf-8")
    memory.write_text("hol-guard release notes\n", encoding="utf-8")

    artifact = _artifact(
        f"sed -n '1,240p' {shlex.quote(str(skill))} && rg -n -i 'hol-guard|release/2.2' {shlex.quote(str(memory))}",
        home=home,
        harness="codex",
    )

    assert artifact is None


def test_compound_rg_ignore_case_does_not_become_sed_in_place(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    source = workspace / "source.txt"
    source.parent.mkdir(parents=True)
    source.write_text("hol-guard\n", encoding="utf-8")

    artifact = _artifact(
        f"sed -n '1,20p' {shlex.quote(str(source))} && rg -i hol-guard {shlex.quote(str(source))}",
        home=home,
        workspace=workspace,
    )

    assert artifact is None
    assert (
        _artifact(
            f"sed -i 's/a/b/' {shlex.quote(str(source))}",
            home=home,
            workspace=workspace,
        )
        is not None
    )


@pytest.mark.parametrize(
    "command",
    (
        "xargs hol-guard uninstall --all",
        "sh -c 'hol-guard policy disable'",
        "parallel plugin-guard clear --all ::: value",
        "HOL-GUARD.EXE uninstall --all",
        "Plugin-Guard.EXE policy disable",
    ),
)
def test_guard_removal_wrappers_keep_the_destructive_floor(
    live_hook_root: Path,
    command: str,
) -> None:
    home = live_hook_root / "home"
    home.mkdir(exist_ok=True)

    artifact = _artifact(command, home=home)

    assert artifact is not None
    assert artifact["reason_code"] == "native_guard_self_protection"


@LIVE_REVIEWS_RETIRED_ALLOW
def test_compound_shell_syntax_check_is_inspection_only(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    script = workspace / "scripts" / "check.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\n", encoding="utf-8")

    command = f"cd {_shell_path(workspace)} && bash -n scripts/check.sh && echo valid"
    assert_leading_cd_inspection_allowed(_artifact(command, home=home))


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "fd -t f --exec rm {}",
        "rg --pre process TODO src",
        'python3 -c "import subprocess; subprocess.run(["sh"])"',
        "find . -delete",
        "cat settings.txt > copied.txt",
        "cat /etc/example.py",
        "cat ../../../../outside/example.py",
        "cd / && cat /etc/example.py",
        "curl https://example.test",
        "bash scripts/check.sh",
        "bash -n ../outside.sh",
    ),
)
def test_compound_recovery_preserves_real_risk_boundaries(live_hook_root: Path, suffix: str) -> None:
    home = live_hook_root / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)
    (workspace / "src").mkdir()
    (workspace / "settings.txt").write_text("public\n", encoding="utf-8")

    assert _artifact(f"cd {_shell_path(workspace)} && {suffix}", home=home) is not None
