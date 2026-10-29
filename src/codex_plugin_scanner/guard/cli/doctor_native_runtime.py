"""Privacy-safe native availability diagnostics, separate from hook readiness."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal, NotRequired, TypedDict

from ..adapters.diagnostic_probes import skipped_command_probe
from ..native_policy_snapshot_constants import NATIVE_RUNTIME_STATE_DIRECTORY
from ..native_resident_watchdog import published_process_alive, published_resident_process
from ..resident_state_prune import probe_owner_lock
from .doctor_native_diagnosis import native_runtime_diagnosis, native_runtime_message


class _NativeAvailabilityFields(TypedDict):
    mode: Literal["off", "shadow", "auto", "force", "unknown"]
    available: bool | None
    compatible: bool | None
    reason_code: str
    evaluation_verified: Literal[False]


class NativeAvailabilityResult(_NativeAvailabilityFields, total=False):
    message: str


_MAX_STATE_BYTES = 64 * 1024


def _published_generations(state_base: Path, runtime_sha256: str) -> tuple[int, bool]:
    """Count the generations published for this runtime and say whether one is live.

    Liveness follows the same rule the resident watchdog applies: a published
    pid counts only while it is still the process the state file named, so a
    reused pid in state nobody cleaned up is not a running resident.

    Reads only the resident state files; it starts and stops nothing.
    """

    generations = 0
    live = False
    for state_path in state_base.glob("resident-v3-*/generation-*.json"):
        try:
            with state_path.open("rb") as handle:
                state = json.loads(handle.read(_MAX_STATE_BYTES + 1)[:_MAX_STATE_BYTES])
        except (OSError, ValueError):
            continue
        if not isinstance(state, dict) or state.get("runtime_sha256") != runtime_sha256:
            continue
        generations += 1
        published = published_resident_process(state)
        if published is not None and published_process_alive(*published):
            live = True
    return generations, live


def _resident_owned_elsewhere(state_base: Path, runtime_sha256: str) -> bool:
    """True when a process holds the home-wide owner lock and no live resident runs this runtime.

    Reads only the lock and the resident state files; it never takes the lock
    for longer than the probe and never starts or stops a resident.
    """

    if probe_owner_lock(state_base) is not False:
        return False
    return not _published_generations(state_base, runtime_sha256)[1]


def _passive_runtime_sha256() -> str | None:
    """Hash the first valid runtime binary without running it."""

    from ..native_binary_identity import validate_native_binary
    from ..native_runtime import _runtime_candidates

    for candidate in _runtime_candidates():
        identity = validate_native_binary(candidate)
        if identity is not None:
            return identity.sha256
    return None


def _owner_busy(guard_home: Path | None, runtime_sha256: str | None) -> bool:
    return (
        guard_home is not None
        and runtime_sha256 is not None
        and _resident_owned_elsewhere(guard_home / NATIVE_RUNTIME_STATE_DIRECTORY, runtime_sha256)
    )


def _with_reason(result: NativeAvailabilityResult, reason: str) -> NativeAvailabilityResult:
    result["reason_code"] = reason
    message = native_runtime_message(reason)
    if message is not None:
        result["message"] = message
    return result


def _passive_availability(guard_home: Path | None) -> NativeAvailabilityResult:
    """Answer as far as reading the installed files allows, without running them.

    Installation is decidable passively: a runtime binary either validates
    against its recorded identity or it does not, so ``available`` is a real
    answer rather than a null one. Compatibility is not decidable this way,
    because the capabilities a build reports can only be read from the build
    itself, so it stays null and the message names that limit.
    """

    from ..native_runtime import native_mode

    runtime_sha256 = _passive_runtime_sha256()
    result: NativeAvailabilityResult = {
        # ``native_mode`` reads the environment only; it starts nothing.
        "mode": native_mode(),
        "available": runtime_sha256 is not None,
        "compatible": None,
        "reason_code": "native_status_probe_skipped",
        "evaluation_verified": False,
    }
    # The owner lock and the binary hash are read without running anything.
    if _owner_busy(guard_home, runtime_sha256):
        return _with_reason(result, "native_resident_owner_busy")
    return _with_reason(result, "native_status_probe_skipped")


def doctor_native_availability(guard_home: Path | None = None) -> NativeAvailabilityResult:
    """Report native availability, never a failure the caller did not let us check."""
    # This only queries the passive scope; its command metadata is not emitted.
    if skipped_command_probe(["hol-guard-runtime", "capabilities", "--json"]) is not None:
        return _passive_availability(guard_home)

    from ..native_runtime import native_runtime_status

    try:
        status = native_runtime_status()
    except (OSError, RuntimeError, ValueError):
        return {
            "mode": "unknown",
            "available": False,
            "compatible": False,
            "reason_code": "native_status_probe_failed",
            "evaluation_verified": False,
        }
    reason = status.reason
    # Native status reasons are fixed lowercase codes, not arbitrary probe text.
    if not re.fullmatch(r"[a-z0-9_.-]{1,96}", reason):
        reason = "native_status_reason_unavailable"
    result: NativeAvailabilityResult = {
        "mode": status.mode,
        "available": status.available,
        "compatible": status.compatible,
        "reason_code": reason,
        "evaluation_verified": False,
    }
    identity = status.identity
    if _owner_busy(guard_home, identity.sha256 if identity is not None else None):
        reason = "native_resident_owner_busy"
    return _with_reason(result, reason)


class NativeResidentPresence(TypedDict):
    """What the on-disk resident state says, without starting or stopping anything."""

    live: bool | None
    owner_lock_held: bool | None
    generations: int
    # The serving resident's own answer about itself, present only when one was
    # already running and answered. Its absence is not a fault: it says the
    # question went unanswered, never that the resident is unhealthy.
    serving: NotRequired[dict[str, Any] | None]


def native_resident_presence(guard_home: Path | None, runtime_sha256: str | None) -> NativeResidentPresence:
    """Report whether a resident for this runtime is already running on this account.

    Unlike the admission and health counters, which only ever describe the
    current process, this reads the files every Guard install on the account
    shares, so a separate CLI invocation sees the same answer the hook does.
    """

    if guard_home is None or runtime_sha256 is None:
        return {"live": None, "owner_lock_held": None, "generations": 0}
    state_base = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    owner_lock = probe_owner_lock(state_base)
    generations, live = _published_generations(state_base, runtime_sha256)
    return {
        "live": live,
        # ``probe_owner_lock`` returns None when it could not tell.
        "owner_lock_held": None if owner_lock is None else owner_lock is False,
        "generations": generations,
    }


def native_runtime_section(
    guard_home: Path | None,
    *,
    repair: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the ``native_runtime`` payload doctor reports and ``runtime status`` prints.

    Every field here is read from a passive probe, the installed binary's
    identity, or process-local counters. Nothing is evaluated and no verdict is
    produced: the native resident remains the only authority.
    """

    from ..daemon.bounded_http import daemon_admission_snapshot
    from .update_commands import bundled_native_runtime_report

    availability = doctor_native_availability(guard_home)
    resident = native_resident_presence(guard_home, _passive_runtime_sha256())
    if resident["live"] is True and guard_home is not None:
        # Only ever asked of a resident that is already serving, so the report
        # stays a passive observation. The question rides the resident's
        # reserved control lane, so a busy resident answers it too: a published
        # pid alone cannot tell a wedged resident from a working one.
        from ..native_resident_health import native_resident_health

        resident["serving"] = native_resident_health(guard_home=guard_home)
    section: dict[str, object] = {
        "availability": availability,
        # The HTTP gate counts this process only; a fresh CLI invocation
        # reports its own zeros, not the daemon's totals.
        "daemon_http": daemon_admission_snapshot(),
        "resident": resident,
    }
    # A reason code is the runtime layer's word for its own decision. When that
    # decision leaves protection off, the report also has to say what is wrong
    # and what fixes it, which the code itself never does.
    diagnosis = native_runtime_diagnosis(availability["reason_code"], available=availability["available"])
    if diagnosis is not None:
        section["diagnosis"] = diagnosis
    bundled_runtime = bundled_native_runtime_report()
    if bundled_runtime is not None:
        section["bundled"] = bundled_runtime
    if repair is not None:
        section["repair"] = repair
    return section
