"""``hol-guard plugin install|uninstall``: install a HOL listing with each runtime's own CLI.

Guard asks HOL for the listing's install spec (identifiers and the scan
result), the native Kit checks every identifier, decides whether HOL's scan
lets the install go ahead, and turns the spec into argument vectors for fixed
programs; this module prints that plan. Nothing runs unless ``--apply`` is
passed, and then only after a confirmation per runtime (``--yes`` skips the
prompts for CI, but never accepts a risk or a declared command on its own).
Commands run without a shell or stdin; see ``runner``.

Exit codes: 0 done or plan shown; 1 a runtime command or check failed; 2 usage,
or no terminal to confirm in; 3 nothing Guard can install here; 4 stopped by
HOL's scan result, a commit other than the scanned one, or a declared command
that was not accepted; 5 this Guard is too old; 6 HOL unreachable; 130
interrupted.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from packaging.version import InvalidVersion, Version

from ...version import __version__
from ..mdm.network import ManagedNetworkError, managed_urlopen
from . import runner

SPEC_URL = "https://hol.org/api/guard/plugins/install-spec"
#: Points Guard at another install-spec endpoint, such as a local portal with
#: test listings. https anywhere; plain http only on this machine or the
#: Docker host. Listing pages must then live on the same origin.
SPEC_URL_ENV = "HOL_GUARD_PLUGIN_SPEC_URL"
VIA_GUARD = "hol-guard"
#: The only programs a plan may start. Each is the runtime's own CLI.
PROGRAMS = ("claude", "codex", "npx")
#: The newest install-spec version this Guard reads; HOL answers in it or older.
SPEC_SCHEMA = 2
_SPEC_LIMIT_BYTES = 64 * 1024
_SPEC_TIMEOUT_SECONDS = 20.0
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")

EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_NOTHING = 3
EXIT_STOPPED = 4
EXIT_TOO_OLD = 5
EXIT_UNREACHABLE = 6
EXIT_INTERRUPTED = 130


class PluginInstallError(RuntimeError):
    """The install could not be planned or a command failed."""

    def __init__(self, message: str, *, exit_code: int = EXIT_USAGE, code: str = "invalid") -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.code = code


def parse_target(value: str) -> tuple[str, str | None]:
    """``owner/name[@version]`` -> slug and optional version."""

    slug, _, version = value.strip().partition("@")
    if not slug:
        raise PluginInstallError("Name a HOL listing, such as owner/plugin.")
    return slug, version or None


def spec_endpoint(environ: Mapping[str, str] | None = None) -> tuple[str, str | None]:
    """The install-spec URL, and its origin when the user overrode it.

    The native Kit decides whether an override is allowed and what its origin
    is, so the CLI and the plan check listings against the same rules.
    """

    value = (os.environ if environ is None else environ).get(SPEC_URL_ENV, "").strip()
    if not value:
        return SPEC_URL, None
    from .cli import PluginKitNativeError, kit_request

    try:
        origin = kit_request({"command": "endpoint", "value": value}).get("origin")
    except PluginKitNativeError as error:
        raise PluginInstallError(str(error)) from None
    if not isinstance(origin, str):
        raise PluginInstallError(f"{SPEC_URL_ENV} could not be checked. Reinstall hol-guard.")
    return value, origin


def fetch_spec(slug: str, endpoint: str = SPEC_URL) -> dict[str, Any]:
    url = f"{endpoint}?{urllib.parse.urlencode({'slug': slug, 'schema': SPEC_SCHEMA})}"
    request = urllib.request.Request(
        url, headers={"User-Agent": f"hol-guard/{__version__}", "Accept": "application/json"}
    )
    try:
        # An override was checked as given; a redirect would leave those checks behind.
        with managed_urlopen(request, timeout=_SPEC_TIMEOUT_SECONDS, allow_redirects=endpoint == SPEC_URL) as response:
            raw = response.read(_SPEC_LIMIT_BYTES + 1)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise PluginInstallError(
                f"{SPEC_URL_ENV} answered with a redirect. Set it to the final install-spec URL."
            ) from error
        if error.code == 404:
            raise PluginInstallError(f"No plugin {slug} is listed on HOL.", code="not_found") from error
        if error.code == 410:
            raise PluginInstallError(f"{slug} was removed from HOL.", code="removed") from error
        if error.code == 400:
            raise PluginInstallError("Use a HOL listing slug such as owner/plugin.") from error
        raise PluginInstallError(
            f"HOL could not answer right now (HTTP {error.code}). Try again shortly.",
            exit_code=EXIT_UNREACHABLE,
            code="unreachable",
        ) from error
    except (ManagedNetworkError, urllib.error.URLError, OSError) as error:
        raise PluginInstallError(
            "The install details could not be downloaded from HOL.", exit_code=EXIT_UNREACHABLE, code="unreachable"
        ) from error
    if len(raw) > _SPEC_LIMIT_BYTES:
        raise PluginInstallError("The install details from HOL were larger than expected.")
    try:
        spec = json.loads(raw)
    except ValueError as error:
        raise PluginInstallError("The install details from HOL were not valid JSON.") from error
    if not isinstance(spec, dict):
        raise PluginInstallError("The install details from HOL were not in the expected shape.")
    return spec


def read_spec_file(path: str) -> dict[str, Any]:
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PluginInstallError("The spec file could not be read as JSON.") from error
    if not isinstance(spec, dict):
        raise PluginInstallError("The spec file is not a JSON object.")
    return spec


def check_guard_version(spec: Mapping[str, Any], running: str = __version__) -> None:
    """Refuse a listing that needs a newer Guard than this one."""

    needed = spec.get("minGuardVersion")
    if needed is None:
        return
    try:
        too_old = Version(running) < Version(str(needed))
    except InvalidVersion as error:
        raise PluginInstallError(
            "HOL asked for a Guard version this Guard cannot read. Run: hol-guard update",
            exit_code=EXIT_TOO_OLD,
            code="guard_too_old",
        ) from error
    if too_old:
        raise PluginInstallError(
            f"This listing needs hol-guard {needed} or newer; this is {running}. Run: hol-guard update",
            exit_code=EXIT_TOO_OLD,
            code="guard_too_old",
        )


def find_programs(environ: Mapping[str, str] | None = None) -> runner.Lookup:
    return runner.find_programs(PROGRAMS, environ)


def recorded_installs(guard_home: Path) -> dict[str, list[str]]:
    """Listings ``plugin install --apply`` installed, as ``{slug: [runtime, ...]}``.

    The record lives in the native Kit; without it nothing is marked.
    """

    from .cli import PluginKitNativeError, kit_request

    try:
        result = kit_request({"command": "installs", "guard_home": str(guard_home)})
    except PluginKitNativeError:
        return {}
    return {
        slug: [runtime for runtime in runtimes if isinstance(runtime, str)]
        for slug, runtimes in result.items()
        if isinstance(runtimes, list)
    }


def record(
    guard_home: Path,
    slug: str,
    runtime: str,
    *,
    installed: bool,
    spec: Mapping[str, Any] | None = None,
    listing_origin: str | None = None,
) -> None:
    """Add a runtime to Guard's install record (``spec`` is the one installed) or drop it."""

    from .cli import PluginKitNativeError, kit_request

    request: dict[str, object] = {
        "command": "record",
        "guard_home": str(guard_home),
        "slug": slug,
        "runtime": runtime,
        "installed": installed,
    }
    if listing_origin:
        request["listing_origin"] = listing_origin
    if installed:
        request["spec"] = dict(spec or {})
    try:
        kit_request(request)
    except PluginKitNativeError as error:
        raise PluginInstallError(str(error)) from error


def mark_guard_installs(report: Mapping[str, Any], guard_home: Path) -> dict[str, Any]:
    """Tag report entries for listings ``plugin install --apply`` installed."""

    ledger = recorded_installs(guard_home)
    marked = dict(report)
    entries = report.get("entries")
    if isinstance(entries, list):
        marked["entries"] = [
            {**entry, "via": VIA_GUARD}
            if isinstance(entry, dict) and entry.get("runtime") in ledger.get(str(entry.get("slug")), [])
            else entry
            for entry in entries
        ]
    return marked


def _shown(argv: Sequence[str]) -> str:
    return " ".join(argv)


def _short(commit: object) -> str:
    return commit[:7] if isinstance(commit, str) and commit else "unknown"


def _printable(text: str) -> str:
    """Escape control and format characters a runtime CLI reported."""

    return "".join(
        f"\\u{ord(character):04x}" if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in text
    )


def _verb(action: str) -> str:
    return "Install" if action == "install" else "Uninstall"


_GATE_TEXT = {
    "pass": "Passed HOL's checks.",
    "confirm": "Needs your OK before Guard installs it.",
    "block": "Blocked. Guard will not install it.",
}


def write_security(security: Mapping[str, Any] | None, out: TextIO | None) -> None:
    if not security:
        return
    print(f"  Security: {_GATE_TEXT.get(str(security.get('gate')), 'Unknown.')}", file=out)
    scanned_at, scanned_ref = security.get("scanned_at"), security.get("scanned_ref")
    findings = security.get("findings")
    if isinstance(scanned_at, str):
        line = f"    Scanned {scanned_at[:10]}"
        if isinstance(scanned_ref, str):
            line += f" at {scanned_ref[:7]}"
        if isinstance(findings, dict):
            line += f": {findings.get('critical', 0)} critical, {findings.get('high', 0)} high."
        print(line if line.endswith(".") else f"{line}.", file=out)
    for reason in security.get("reasons") or []:
        print(f"    {reason}", file=out)
    for reason in security.get("hol_reasons") or []:
        print(f"    HOL: {reason}", file=out)
    if security.get("report_url"):
        print(f"    Report: {security['report_url']}", file=out)


def write_plan(plan: Mapping[str, Any], lookup: runner.Lookup, *, apply: bool, out: TextIO | None = None) -> None:
    out = out or sys.stdout
    action = plan.get("action")
    version = f" {plan['version']}" if plan.get("version") else ""
    print(f"{plan.get('slug')}{version}", file=out)
    write_security(plan.get("security"), out)
    if isinstance(plan.get("trust_score"), int | float):
        print(f"  HOL trust score: {plan['trust_score']:g}/100", file=out)
    print(f"  Listing: {plan.get('listing_url')}", file=out)
    steps = plan.get("steps") or []
    if not steps:
        print("\nHOL has no install Guard can run for this listing. Follow the listing's install steps.", file=out)
    for step in steps:
        program = lookup.programs.get(str(step.get("program")))
        if program is not None:
            state = f"  ({program.path})" if step.get("automatic") else ""
        else:
            state = f"  ({step.get('program')} not found)"
        print(f"\n{step.get('runtime')}:{state}", file=out)
        for argv in step.get("commands") or []:
            print(f"  {_shown(argv)}", file=out)
        if step.get("note"):
            print(f"  {step['note']}", file=out)
    manual = plan.get("manual") or []
    if manual:
        print(f"\nInstall by hand (see the listing): {', '.join(manual)}", file=out)
    gate = (plan.get("security") or {}).get("gate")
    runnable = any(step.get("automatic") and str(step.get("program")) in lookup.programs for step in steps)
    if not apply and runnable and gate != "block":
        verb = "install" if action == "install" else "uninstall"
        print(f"\nNothing was changed. Run with --apply to {verb}, confirming each runtime.", file=out)


@dataclass
class Outcome:
    """What happened for one runtime; ``status`` is one of planned, skipped,
    declined, installed, removed, failed or blocked."""

    runtime: str
    status: str
    path: str | None = None
    exit_code: int | None = None
    message: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "status": self.status,
            "path": self.path,
            "exit_code": self.exit_code,
            "message": self.message,
        }


def planned(plan: Mapping[str, Any], lookup: runner.Lookup) -> list[Outcome]:
    outcomes = []
    for step in plan.get("steps") or []:
        runtime, name = str(step.get("runtime")), str(step.get("program"))
        program = lookup.programs.get(name)
        if not step.get("automatic"):
            outcomes.append(Outcome(runtime, "skipped", message="Guard does not run this one; run it yourself."))
        elif program is None:
            outcomes.append(Outcome(runtime, "skipped", message=f"{name} was not found."))
        else:
            outcomes.append(Outcome(runtime, "planned", program.path))
    return outcomes


def exit_code_for(outcomes: Sequence[Outcome]) -> int:
    if any(outcome.status == "blocked" for outcome in outcomes):
        return EXIT_STOPPED
    if any(outcome.status == "failed" for outcome in outcomes):
        return EXIT_FAILED
    return 0


def confirm(question: str) -> bool:
    """Ask on stderr, so stdout stays clean for ``--json``; anything but yes is no."""

    sys.stderr.write(f"{question} [y/N] ")
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    return answer.strip().lower() in {"y", "yes"}


class _StoppedError(Exception):
    def __init__(self, status: str, message: str, exit_code: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code


def _reply(stdout: str) -> dict[str, Any]:
    """The JSON object a runtime CLI printed with ``--json``, or ``{}``."""

    for candidate in (stdout, *reversed(stdout.strip().splitlines())):
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return {}


def _ran(completed: runner.Completed, argv: Sequence[str], reply: Mapping[str, Any] | None = None) -> None:
    if completed.returncode == 0:
        return
    message = (reply or {}).get("message")
    detail = f": {_printable(message)}" if isinstance(message, str) and message else "."
    raise _StoppedError("failed", f"{argv[0]} exited with {completed.returncode}{detail}", completed.returncode)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def claude_home(environ: Mapping[str, str] | None = None) -> Path:
    configured = (os.environ if environ is None else environ).get("CLAUDE_CONFIG_DIR", "").strip()
    return Path(configured) if configured else Path.home() / ".claude"


def _claude_marketplace_source(home: Path, name: str) -> str | None:
    """The GitHub repository a known Claude Code marketplace comes from, ``""`` for
    any other source, or None when no marketplace has that name."""

    known = _read_json(home / "plugins" / "known_marketplaces.json")
    entry = known.get(name) if isinstance(known, dict) else None
    if not isinstance(entry, dict):
        return None
    source = entry.get("source")
    if not isinstance(source, dict):
        return ""
    if isinstance(source.get("repo"), str):
        return source["repo"].lower()
    url = source.get("url")
    match = re.fullmatch(r"https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?", url) if isinstance(url, str) else None
    return match.group(1).lower() if match else ""


def _claude_install(home: Path, plugin_id: str) -> tuple[bool, str | None]:
    """Whether Claude Code has the plugin for the user, and the commit it installed."""

    data = _read_json(home / "plugins" / "installed_plugins.json")
    plugins = data.get("plugins") if isinstance(data, dict) else None
    entries = plugins.get(plugin_id) if isinstance(plugins, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and entry.get("scope") == "user":
            commit = entry.get("gitCommitSha")
            return True, commit if isinstance(commit, str) else None
    return False, None


def git_head(root: Path) -> str | None:
    """The commit a checkout is at, read from its files without running git."""

    git = root / ".git"
    try:
        if git.is_file():
            pointer = git.read_text(encoding="utf-8").strip()
            if not pointer.startswith("gitdir:"):
                return None
            git = (root / pointer[len("gitdir:") :].strip()).resolve()
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if _COMMIT.fullmatch(head):
            return head
        if not head.startswith("ref: refs/") or ".." in head:
            return None
        ref = head[len("ref: ") :]
        loose = git / ref
        if loose.is_file():
            commit = loose.read_text(encoding="utf-8").strip()
            return commit if _COMMIT.fullmatch(commit) else None
        for line in (git / "packed-refs").read_text(encoding="utf-8").splitlines():
            commit, _, name = line.partition(" ")
            if name == ref and _COMMIT.fullmatch(commit):
                return commit
    except (OSError, UnicodeDecodeError):
        return None
    return None


@dataclass
class _Context:
    action: str
    assume_yes: bool
    accept_command: str | None
    ask: Callable[[str], bool]
    echo: TextIO | None
    out: TextIO
    home: Path


def _run_step(program: runner.Program, argv: Sequence[str], context: _Context) -> None:
    print(f"$ {_shown(argv)}", file=context.out)
    _ran(runner.run(program, argv[1:], echo=context.echo), argv)


def _undo(program: runner.Program, argv: Sequence[str], context: _Context) -> str:
    """Run a rollback command; on failure, say how to run it by hand."""

    try:
        if runner.run(program, argv[1:], echo=context.echo).returncode == 0:
            return ""
    except runner.RunnerError:
        pass
    return f" Remove it yourself with: {_shown(argv)}"


def _declared_command(reply: Mapping[str, Any], context: _Context) -> str:
    shown = reply.get("shownCommand")
    command = shown.get("command") if isinstance(shown, dict) else None
    digest = shown.get("sha256") if isinstance(shown, dict) else None
    if not isinstance(command, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise _StoppedError("blocked", "Claude Code reported an install command Guard could not read, so nothing ran.")
    print("\nclaude-code: this plugin runs a command on your machine when it installs:", file=context.out)
    print(f"  {_printable(command)}", file=context.out)
    print(f"  sha256 {digest}", file=context.out)
    return digest


def _install_claude(step: Mapping[str, Any], program: runner.Program, context: _Context) -> None:
    """Install through Claude Code, show any command the plugin declares, then
    check Claude Code installed the commit HOL scanned."""

    add, install = step["commands"]
    marketplace, plugin_id = str(step.get("marketplace")), str(step.get("plugin_id"))
    expected = step.get("expected_commit")
    remove_marketplace = ["claude", "plugin", "marketplace", "remove", marketplace]
    source = _claude_marketplace_source(context.home, marketplace)
    if source is not None and source != str(add[-1]).lower():
        raise _StoppedError(
            "blocked",
            f"Claude Code already has a marketplace named {marketplace} from another source, "
            "so Guard did not install from it.",
        )
    had_plugin, prior = _claude_install(context.home, plugin_id)
    if had_plugin and expected and prior != expected:
        raise _StoppedError(
            "blocked",
            f"Claude Code already has {plugin_id} at commit {_short(prior)}, not the commit HOL scanned "
            f"({_short(expected)}), so Guard did not change it. To install what HOL scanned, remove it first "
            f"with: claude plugin uninstall {plugin_id}",
        )
    added = source is None
    if added:
        _run_step(program, add, context)

    def undo_marketplace() -> str:
        return _undo(program, remove_marketplace, context) if added else ""

    def run_install(arguments: Sequence[str]) -> runner.Completed:
        """Run Claude Code's install; if it never finishes, take back what
        Guard added before reporting the failure."""

        try:
            return runner.run(program, arguments, capture=True)
        except runner.RunnerError as error:
            undone = ""
            if not had_plugin and _claude_install(context.home, plugin_id)[0]:
                undone = _undo(program, ["claude", "plugin", "uninstall", plugin_id], context)
            undone += undo_marketplace()
            raise runner.RunnerError(
                f"{error}{undone}" if undone else f"{error} Guard removed what it added."
            ) from None

    arguments = [*install[1:], "--json"]
    print(f"$ {_shown(install)}", file=context.out)
    completed = run_install(arguments)
    reply = _reply(completed.stdout)
    if completed.returncode != 0 and reply.get("failureCode") == "command_source_refused":
        try:
            digest = _declared_command(reply, context)
        except _StoppedError as stop:
            raise _StoppedError(stop.status, f"{stop}{undo_marketplace()}") from None
        accepted = context.accept_command
        if accepted is None and not context.assume_yes and context.ask("Let Claude Code run this command?"):
            accepted = digest
        if accepted != digest:
            reason = (
                "--accept-command does not match the command this plugin declares, so nothing ran."
                if accepted
                else f"The install command was not accepted, so nothing ran. To run it, add --accept-command {digest}."
            )
            raise _StoppedError("blocked", f"{reason}{undo_marketplace()}")
        completed = run_install([*arguments, "--accept-command", digest])
        reply = _reply(completed.stdout)
    try:
        _ran(completed, install, reply)
    except _StoppedError as stop:
        raise _StoppedError(stop.status, f"{stop}{undo_marketplace()}", stop.exit_code) from None
    if not expected:
        return
    _, commit = _claude_install(context.home, plugin_id)
    if commit == expected:
        return
    if had_plugin:
        raise _StoppedError(
            "blocked",
            f"Claude Code moved {plugin_id} from commit {_short(prior)} to {_short(commit)}, not the commit HOL "
            f"scanned ({_short(expected)}). Remove it with: claude plugin uninstall {plugin_id}",
        )
    undone = _undo(program, ["claude", "plugin", "uninstall", plugin_id], context) + undo_marketplace()
    raise _StoppedError(
        "blocked",
        f"Claude Code installed commit {_short(commit)}, not the commit HOL scanned ({_short(expected)}). "
        + (f"Guard could not remove it.{undone}" if undone else "Guard removed it again."),
    )


def _install_codex(step: Mapping[str, Any], program: runner.Program, context: _Context) -> None:
    """Add the marketplace at the scanned commit, check Codex checked that commit
    out, then install the plugin."""

    add, plugin_add = step["commands"]
    expected = step.get("expected_commit")
    if not expected:
        _run_step(program, add, context)
        _run_step(program, plugin_add, context)
        return
    print(f"$ {_shown(add)}", file=context.out)
    completed = runner.run(program, [*add[1:], "--json"], capture=True)
    reply = _reply(completed.stdout)
    _ran(completed, add, reply)
    root, already = reply.get("installedRoot"), reply.get("alreadyAdded")
    head = git_head(Path(root)) if isinstance(root, str) and os.path.isabs(root) else None
    if head != expected:
        marketplace = str(step.get("marketplace"))
        remove = ["codex", "plugin", "marketplace", "remove", marketplace]
        # Only take back a marketplace Codex says it just added; one the
        # user added before, or one Codex did not say, stays.
        if already is False:
            hint = _undo(program, remove, context)
        elif already is True:
            hint = f" You added that marketplace before; to install what HOL scanned, remove it with: {_shown(remove)}"
        else:
            hint = (
                " Codex did not say whether it added that marketplace, so Guard left it. "
                f"If you did not add it, remove it with: {_shown(remove)}"
            )
        raise _StoppedError(
            "blocked",
            f"Codex has the {marketplace} marketplace at commit {_short(head)}, not the commit HOL scanned "
            f"({_short(expected)}), so Guard did not install the plugin.{hint}",
        )
    _run_step(program, plugin_add, context)


def apply_plan(
    plan: Mapping[str, Any],
    *,
    lookup: runner.Lookup,
    assume_yes: bool,
    record: Callable[[str], None],
    accept_command: str | None = None,
    ask: Callable[[str], bool] = confirm,
    json_output: bool = False,
    home: Path | None = None,
    progress: Callable[[Sequence[Outcome]], None] | None = None,
) -> list[Outcome]:
    """Run each automatic step the user confirms, then ``record`` its runtime.
    ``progress`` sees the outcomes so far after each runtime, so an interrupt
    still reports the ones that finished."""

    action = str(plan.get("action"))
    context = _Context(
        action=action,
        assume_yes=assume_yes,
        accept_command=accept_command,
        ask=ask,
        echo=sys.stderr if json_output else None,
        out=sys.stderr if json_output else sys.stdout,
        home=home or claude_home(),
    )
    outcomes: list[Outcome] = []

    def add(outcome: Outcome) -> None:
        outcomes.append(outcome)
        if progress is not None:
            progress(outcomes)

    for step in plan.get("steps") or []:
        runtime, name = str(step.get("runtime")), str(step.get("program"))
        program = lookup.programs.get(name)
        if not step.get("automatic"):
            add(Outcome(runtime, "skipped", message="Guard does not run this one; run it yourself."))
            continue
        if program is None:
            print(f"\n{runtime}: skipped, {name} is not installed.", file=context.out)
            add(Outcome(runtime, "skipped", message=f"{name} was not found."))
            continue
        commands = step.get("commands") or []
        if any(not argv or str(argv[0]) != name for argv in commands):
            raise PluginInstallError("The install plan was not in the expected shape.", exit_code=EXIT_FAILED)
        if not assume_yes and not ask(f"{_verb(action)} for {runtime} with {program.path}?"):
            print(f"{runtime}: skipped.", file=context.out)
            add(Outcome(runtime, "declined", program.path))
            continue
        try:
            if action == "install" and runtime == "claude-code" and len(commands) == 2:
                _install_claude(step, program, context)
            elif action == "install" and runtime == "codex" and len(commands) == 2:
                _install_codex(step, program, context)
            else:
                for argv in commands:
                    _run_step(program, [str(part) for part in argv], context)
        except _StoppedError as stop:
            print(f"{runtime}: {stop}", file=sys.stderr)
            add(Outcome(runtime, stop.status, program.path, stop.exit_code, str(stop)))
            continue
        except runner.RunnerError as error:
            print(f"{runtime}: {error}", file=sys.stderr)
            add(Outcome(runtime, "failed", program.path, None, str(error)))
            continue
        verify = step.get("verify")
        done = "installed; start a new session to load it" if action == "install" else "removed"
        check = f" Check with: {_shown(verify)}" if verify else ""
        print(f"{runtime}: {done}.{check}", file=context.out)
        try:
            record(runtime)
        except PluginInstallError as error:
            message = f"{error} Guard's record of this listing may be out of date."
            print(f"{runtime}: {message}", file=sys.stderr)
            add(Outcome(runtime, "failed", program.path, 0, message))
            continue
        add(Outcome(runtime, "installed" if action == "install" else "removed", program.path, 0))
    return outcomes
