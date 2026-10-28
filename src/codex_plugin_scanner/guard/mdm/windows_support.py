"""Shared Windows system-path discovery for MDM operations."""

from __future__ import annotations

import ntpath


def windows_directory() -> str:
    """Return the normalized Windows system root or raise when unavailable."""

    import ctypes

    buffer = ctypes.create_unicode_buffer(32_768)
    length = int(ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buffer, len(buffer)))
    if length == 0 or length >= len(buffer):
        raise OSError("windows_system_directory_unavailable")
    return ntpath.normpath(str(buffer.value))
