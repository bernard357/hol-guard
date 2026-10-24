"""Bounded, symlink-refusing file access for reviewed manifest fixes.

Every path is a relative path under the admitted root. Each directory on the
way and the manifest itself must be a plain directory or regular file: a
symlink or reparse point anywhere is refused, and the manifest is opened with
``O_NOFOLLOW`` and checked against the entry that was inspected. The write goes
through the shared atomic no-follow writer; nothing here runs a package
manager or any project code.
"""

from __future__ import annotations

import os
import stat
from collections import deque
from pathlib import Path, PurePosixPath
from typing import Final

from ..safe_output import write_bytes_atomic_no_follow

MANIFEST_NAME: Final = "package.json"
MAX_MANIFEST_BYTES: Final = 1024 * 1024
MAX_SCAN_DIRECTORIES: Final = 2_000
MAX_SCAN_DEPTH: Final = 12
MAX_MANIFESTS: Final = 200
LOCKFILE_NAMES: Final = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
)
_REPARSE_POINT: Final = 0x400


class ManifestAccessError(OSError):
    """A manifest could not be opened safely; ``code`` says why."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def discover_manifests(root: Path) -> tuple[list[str], bool]:
    """Relative ``package.json`` paths under ``root`` and whether the scan stopped early.

    Dependency directories, dot-directories and symlinked directories are not
    entered. A symlinked ``package.json`` is listed so reading it can refuse it
    by name instead of silently treating the package as undeclared.
    """

    manifests: list[str] = []
    pending: deque[tuple[Path, tuple[str, ...]]] = deque([(root, ())])
    scanned = 0
    while pending:
        if scanned >= MAX_SCAN_DIRECTORIES:
            return sorted(manifests), True
        directory, parts = pending.popleft()
        scanned += 1
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            continue
        for entry in children:
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_directory:
                if len(parts) < MAX_SCAN_DEPTH and entry.name != "node_modules" and not entry.name.startswith("."):
                    pending.append((Path(entry.path), (*parts, entry.name)))
            elif entry.name == MANIFEST_NAME:
                if len(manifests) >= MAX_MANIFESTS:
                    return sorted(manifests), True
                manifests.append(PurePosixPath(*parts, entry.name).as_posix())
    return sorted(manifests), False


def read_manifest(root: Path, relative: str) -> tuple[bytes, int]:
    """The manifest's bytes and permission bits, read without following links."""

    target = _checked_path(root, relative)
    try:
        inspected = target.lstat()
    except FileNotFoundError as error:
        raise ManifestAccessError("manifest_missing") from error
    except OSError as error:
        raise ManifestAccessError("manifest_unreadable") from error
    if _is_link(inspected):
        raise ManifestAccessError("manifest_is_symlink")
    if not stat.S_ISREG(inspected.st_mode):
        raise ManifestAccessError("manifest_not_regular")
    if inspected.st_size > MAX_MANIFEST_BYTES:
        raise ManifestAccessError("manifest_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise ManifestAccessError("manifest_unreadable") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (inspected.st_dev, inspected.st_ino):
            raise ManifestAccessError("manifest_changed")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as error:
        if isinstance(error, ManifestAccessError):
            raise
        raise ManifestAccessError("manifest_unreadable") from error
    finally:
        os.close(descriptor)
    if len(content) > MAX_MANIFEST_BYTES:
        raise ManifestAccessError("manifest_too_large")
    return content, stat.S_IMODE(inspected.st_mode)


def write_manifest(root: Path, relative: str, content: bytes, *, mode: int) -> None:
    """Atomically replace the manifest: same-directory temp file, fsync, rename."""

    write_bytes_atomic_no_follow(_checked_path(root, relative), content, mode=mode)


def lockfiles_for(root: Path, relative: str) -> list[str]:
    """Lockfiles beside the manifest, else the nearest ones in a parent up to the root."""

    parts = PurePosixPath(relative).parts[:-1]
    while True:
        directory = root.joinpath(*parts)
        found = [
            PurePosixPath(*parts, name).as_posix()
            for name in LOCKFILE_NAMES
            if _exists_without_following(directory / name)
        ]
        if found or not parts:
            return found
        parts = parts[:-1]


def _checked_path(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if (
        not parts
        or PurePosixPath(relative).is_absolute()
        or "\\" in relative
        or any(part in {"..", "."} for part in parts)
        or parts[-1] != MANIFEST_NAME
    ):
        raise ManifestAccessError("manifest_path_invalid")
    current = root
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ManifestAccessError("manifest_root_unavailable") from error
    if _is_link(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ManifestAccessError("manifest_root_unavailable")
    for part in parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError as error:
            raise ManifestAccessError("manifest_missing") from error
        except OSError as error:
            raise ManifestAccessError("manifest_unreadable") from error
        if _is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ManifestAccessError("manifest_path_invalid")
    return current / parts[-1]


def _is_link(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)


def _exists_without_following(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return True


__all__ = [
    "LOCKFILE_NAMES",
    "MANIFEST_NAME",
    "MAX_MANIFEST_BYTES",
    "ManifestAccessError",
    "discover_manifests",
    "lockfiles_for",
    "read_manifest",
    "write_manifest",
]
