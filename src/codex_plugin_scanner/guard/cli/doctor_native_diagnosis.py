"""Plain language for a native runtime that is not ready, and the action that changes it.

``doctor --native`` and ``runtime status`` report a reason code. A code names
what the runtime layer decided, not what the person reading it can do, and the
one reason that already carried a message (another install owns the resident)
showed the difference: the code said ``native_resident_owner_busy`` and the
message said nothing crashed. This module answers the second question for the
rest of the reasons, and for the one state a code cannot explain at all.

That state is the common one. Both callers read the installed files without
running them, so a host with no usable runtime reports ``available: no`` under
``native_status_probe_skipped`` -- a reason that describes the probe rather than
the absence. Why each place Guard looks was refused is decidable from file
metadata alone, so this module decides it there and names the slot, never the
path, to keep a pasted report free of home directories and user names.

Nothing here starts a process, repairs a file or produces a verdict.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Literal, TypedDict

CandidateSlot = Literal["override", "bundled", "distribution"]
CandidateState = Literal[
    "absent",
    "not_a_regular_file",
    "untrusted_owner_or_mode",
    "not_executable",
    "unreadable",
    "present",
]


class NativeRuntimeCandidate(TypedDict):
    """One place Guard looks for its runtime, and what the files there say."""

    slot: CandidateSlot
    state: CandidateState


class NativeRuntimeDiagnosis(TypedDict):
    """What is wrong in plain words, the single action that changes it, and the evidence."""

    summary: str
    action: str
    candidates: list[NativeRuntimeCandidate]


_REINSTALL = (
    "Reinstall hol-guard so the runtime bundled with this version is restored: "
    "`uv tool install --force hol-guard` (or `pipx install --force hol-guard`)."
)
_REINSTALL_MATCHED = (
    "Reinstall hol-guard so the Python package and the runtime it bundles come from one "
    "version: `uv tool install --force hol-guard` (or `pipx install --force hol-guard`)."
)

# Two Guard installs (for example a desktop app and a package-manager CLI) share
# one home-wide resident. Only one owns it; the other is healthy, not broken.
_RESIDENT_OWNER_BUSY = (
    "Another Guard install on this account owns the native resident runtime, so this "
    "install cannot start its own. Nothing crashed and no restarts were used. Keep one "
    "Guard install per user, or keep both on the same version so they share one runtime."
)

# Keyed by the reason codes ``native_runtime.py`` and ``doctor_native_runtime.py``
# produce. A reason absent from this table is one that needs no explaining
# (``native_ready``) or one the candidate evidence explains better.
_DIAGNOSES: dict[str, tuple[str, str]] = {
    "native_resident_owner_busy": (_RESIDENT_OWNER_BUSY, "No action is needed; protection is already running."),
    "native_version_mismatch": (
        "The installed runtime was built for a different hol-guard version than the Python "
        "package calling it. Guard will not pair them, because a rule the two disagree about "
        "would be decided differently on each side.",
        _REINSTALL_MATCHED,
    ),
    "native_protocol_mismatch": (
        "The installed runtime speaks a different request protocol than this package. This is "
        "a partial upgrade: one half of the install moved and the other did not.",
        _REINSTALL_MATCHED,
    ),
    "native_manifest_missing": (
        "The runtime binary is installed but the manifest that records what it should be is "
        "not next to it. Guard cannot confirm the binary is the one this version shipped.",
        _REINSTALL,
    ),
    "native_manifest_invalid": (
        "The manifest next to the runtime binary could not be read, or another account can "
        "write to it. Guard will not take an identity from a file it does not trust.",
        _REINSTALL,
    ),
    "native_manifest_runtime_mismatch": (
        "The runtime binary's size and hash are not the ones its own manifest records, so the "
        "binary was replaced or truncated after it was installed.",
        _REINSTALL,
    ),
    "native_manifest_protocol_mismatch": (
        "The runtime reports a different protocol version than its manifest records, so the "
        "binary and the manifest came from different builds.",
        _REINSTALL,
    ),
    "native_manifest_version_mismatch": (
        "The runtime's version does not match its manifest or the installed Python package, "
        "so part of this install is left over from an earlier version.",
        _REINSTALL_MATCHED,
    ),
    "native_manifest_rule_mismatch": (
        "The runtime carries a different rule set than its manifest records. Guard will not "
        "enforce rules it cannot tie back to the build it believes is installed.",
        _REINSTALL,
    ),
    "native_manifest_build_mismatch": (
        "The runtime was built from a different source commit than its manifest records, so "
        "the binary beside the manifest is not the one that manifest describes.",
        _REINSTALL,
    ),
    "native_status_probe_failed": (
        "Guard could not finish reading the installed runtime: the check itself failed rather "
        "than returning an answer.",
        "Run `hol-guard guard doctor --native` again. If it keeps failing, reinstall hol-guard: "
        "`uv tool install --force hol-guard`.",
    ),
    "native_status_reason_unavailable": (
        "The runtime returned a status Guard could not read, so the reason it gave is not "
        "reported here.",
        "Run `hol-guard guard doctor <harness>` for the full check.",
    ),
}

_UNAVAILABLE: dict[CandidateState, tuple[str, str]] = {
    "untrusted_owner_or_mode": (
        "Guard found its native runtime, but the file is owned by another account or is "
        "writable by one. Guard refuses to run a binary that someone else can replace, so "
        "protection stays off rather than running code it does not trust.",
        "Reinstall hol-guard as the account that runs it, without `sudo`: "
        "`uv tool install --force hol-guard`.",
    ),
    "not_executable": (
        "Guard's native runtime is in place but carries no execute permission, so it cannot "
        "be launched. Guard restores that bit on its own bundled copy the next time it runs "
        "the runtime, but it cannot do so on a filesystem mounted `noexec` or on a copy it "
        "does not own, and until the bit is back nothing evaluates a command.",
        "Run `hol-guard guard doctor <harness>` once, which restores the bit on Guard's own "
        "copy. If it stays missing, reinstall hol-guard outside any `noexec` mount: "
        "`uv tool install --force hol-guard`.",
    ),
    "not_a_regular_file": (
        "What Guard found where its runtime belongs is not a regular file. A symlink or a "
        "device in that place is not something Guard will run.",
        _REINSTALL,
    ),
    "unreadable": (
        "Guard's native runtime is in place but could not be read, so its identity could not "
        "be confirmed. A permission on the directory above it will do this.",
        _REINSTALL,
    ),
    "present": (
        "Guard's native runtime is installed and trusted, but it did not answer when asked "
        "what it supports. A runtime that cannot start cannot enforce anything.",
        "Run `hol-guard guard doctor <harness>` to run the full check and see the launch error.",
    ),
    "absent": (
        "This install has no native runtime binary. Guard's Python package is a control plane "
        "only: without the runtime it ships with, nothing evaluates a command, so protection "
        "is off.",
        _REINSTALL,
    ),
}

# Most specific first: an installed-but-refused file explains an unavailable
# runtime better than an empty slot beside it does.
_UNAVAILABLE_ORDER: tuple[CandidateState, ...] = (
    "untrusted_owner_or_mode",
    "not_executable",
    "not_a_regular_file",
    "unreadable",
    "present",
    "absent",
)


# ``availability.message`` reports the one decision that is not a fault: a
# resident another install already owns is working protection, so it needs a
# sentence rather than a repair. Every other explanation belongs to the
# diagnosis, which pairs it with the action that clears it; repeating it here
# would print it twice and carry it twice in the JSON payload.
_REPORTED_AS_MESSAGE = frozenset({"native_resident_owner_busy"})


def native_runtime_message(reason_code: str) -> str | None:
    """The one-paragraph message the availability block itself carries, if any."""

    if reason_code not in _REPORTED_AS_MESSAGE:
        return None
    return _DIAGNOSES[reason_code][0]


def _candidate_state(path: Path) -> CandidateState:
    """Classify one candidate by its metadata alone, matching what validation checks.

    The order follows ``validate_native_binary``: file kind, then ownership and
    mode, so the state names the first check the file would fail. The execute
    bit is checked after those because validation itself does not test it --
    a non-executable binary validates and then fails to launch, which is a
    different repair from a binary nobody trusts.
    """

    from ..group_write_trust import trusted_owner_and_mode

    try:
        metadata = path.expanduser().lstat()
    except FileNotFoundError:
        return "absent"
    except (OSError, RuntimeError, ValueError):
        return "unreadable"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return "not_a_regular_file"
    if os.name == "nt":
        # Windows regular files carry no POSIX ownership or execute semantics
        # Guard reads; identity validation accepts any regular file there.
        return "present"
    try:
        if not trusted_owner_and_mode(metadata, path.expanduser()):
            return "untrusted_owner_or_mode"
    except (OSError, RuntimeError, ValueError):
        return "unreadable"
    if not stat.S_IMODE(metadata.st_mode) & stat.S_IXUSR:
        return "not_executable"
    return "present"


def _candidate_slot(path: Path, override: str | None) -> CandidateSlot:
    from ..native_runtime import _is_bundled_candidate

    if _is_bundled_candidate(path):
        return "bundled"
    if override:
        try:
            if path.expanduser().absolute() == Path(override).expanduser().absolute():
                return "override"
        except (OSError, RuntimeError, ValueError):
            pass
    return "distribution"


def native_runtime_candidates() -> list[NativeRuntimeCandidate]:
    """Say what the files in each place Guard looks are, without naming the places.

    A slot is a role, not a path, so this report can be pasted into an issue:
    ``bundled`` is the runtime inside the installed wheel, ``override`` the one
    an environment variable points at, ``distribution`` a separately installed
    one. Nothing here is executed.
    """

    from ..native_runtime import _NATIVE_BINARY_ENV, _runtime_candidates

    override = os.environ.get(_NATIVE_BINARY_ENV)
    return [
        {"slot": _candidate_slot(path, override), "state": _candidate_state(path)}
        for path in _runtime_candidates()
    ]


def _selected_state(candidates: list[NativeRuntimeCandidate]) -> CandidateState | None:
    """The state of the candidate Guard would actually use.

    ``_compute_runtime_status`` walks the candidates in order and skips every
    one identity validation refuses, so the first candidate it does not refuse
    is the one that decides the outcome.
    """

    refused = {"absent", "not_a_regular_file", "untrusted_owner_or_mode", "unreadable"}
    return next((item["state"] for item in candidates if item["state"] not in refused), None)


def native_runtime_diagnosis(
    reason_code: str,
    *,
    available: bool | None,
) -> NativeRuntimeDiagnosis | None:
    """Explain a runtime that is not ready, or return None when nothing is wrong.

    An unavailable runtime is diagnosed from the candidate files rather than
    from the reason code, because the passive callers report a code about the
    probe they skipped while the files say what is actually missing. The files
    also catch the one broken state no reason code describes: a runtime that
    validates, is reported available, and still cannot be launched.
    """

    candidates = native_runtime_candidates()
    if available is False:
        states = {candidate["state"] for candidate in candidates}
        state = next((item for item in _UNAVAILABLE_ORDER if item in states), "absent")
        summary, action = _UNAVAILABLE[state]
        return {"summary": summary, "action": action, "candidates": candidates}
    # Identity validation never tests the execute bit, so a runtime missing it
    # is reported available and then fails to launch. That gap is the whole
    # reason to look at the files: the reason code cannot see it.
    if _selected_state(candidates) == "not_executable":
        summary, action = _UNAVAILABLE["not_executable"]
        return {"summary": summary, "action": action, "candidates": candidates}
    if reason_code == "native_ready":
        return None
    diagnosis = _DIAGNOSES.get(reason_code)
    if diagnosis is None:
        return None
    return {"summary": diagnosis[0], "action": diagnosis[1], "candidates": candidates}
