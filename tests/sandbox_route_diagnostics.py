"""Host facts a contained-run hook test reports when it gets a review instead."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def sandbox_route_context(workspace_dir: Path) -> dict[str, object]:
    bwrap = shutil.which("bwrap", path="/usr/bin:/bin")
    bwrap_probe: object = None
    if bwrap is not None:
        try:
            completed = subprocess.run(
                [bwrap, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"],
                capture_output=True,
                text=True,
                timeout=10,
                env={"PATH": "/usr/bin:/bin"},
                check=False,
            )
            bwrap_probe = (completed.returncode, completed.stderr.strip()[:200])
        except (OSError, subprocess.TimeoutExpired) as error:
            bwrap_probe = repr(error)
    toplevel = subprocess.run(
        ["git", "-C", str(workspace_dir), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    home = Path(os.environ.get("HOME", "~")).expanduser()
    return {
        "bwrap": bwrap,
        "bwrap_probe": bwrap_probe,
        "userns": _read("/proc/sys/kernel/unprivileged_userns_clone"),
        "apparmor_userns": _read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
        "loadavg": _read("/proc/loadavg"),
        "git_toplevel": toplevel.stdout.strip() or toplevel.returncode,
        "home_gitconfig": (home / ".gitconfig").is_file(),
        "xdg_git_config": (home / ".config" / "git" / "config").is_file(),
        "env_names": sorted(
            name for name in os.environ if name.startswith(("GIT", "XDG", "LD_", "PYTHON", "VIRTUAL", "TMP"))
        ),
    }
