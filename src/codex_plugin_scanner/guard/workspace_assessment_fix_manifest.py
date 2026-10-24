"""Deterministic version edits for ``package.json`` text.

A fix edit replaces only the characters inside one version-spec string, so
every other byte of the manifest (key order, indentation, line endings,
trailing newline) survives. The edit is planned from a scan of the raw text
rather than from a parsed and re-serialized document. Anything that is not a
plain ``major.minor.patch`` range under a recognised dependency section is
refused with a reason code instead of being guessed at.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from typing import Final

from .store_workspace_assessment_schema import MAX_FIX_DIFF_BYTES

# Sections whose entries are direct dependencies of the package itself.
DEPENDENCY_SECTIONS: Final = ("dependencies", "devDependencies", "optionalDependencies")
_PLAIN_SPEC: Final = re.compile(r"^(?P<operator>[\^~]?)(?P<version>\d+\.\d+\.\d+)$")
_PLAIN_VERSION: Final = re.compile(r"^\d+\.\d+\.\d+$")
_STRING: Final = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)
_LITERAL: Final = re.compile(r"[^,\]}\s]+")
_WHITESPACE: Final = re.compile(r"\s*")
_MAX_DEPTH: Final = 100


class FixUnsupportedError(ValueError):
    """The manifest cannot take a safe, minimal edit; ``code`` says why."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class FixEdit:
    section: str
    start: int
    end: int
    from_spec: str
    to_spec: str


@dataclass(frozen=True)
class _Declaration:
    section: str
    start: int
    end: int
    spec: str | None


@dataclass(frozen=True)
class _Member:
    key: str
    value_start: int
    value_end: int


class _Scanner:
    """Walk valid JSON text and report where each value sits."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    def first_value(self) -> int:
        self._skip_whitespace()
        return self._pos

    def members(self, start: int) -> list[_Member]:
        self._pos = start + 1
        found: list[_Member] = []
        while True:
            self._skip_whitespace()
            if self._text[self._pos] == "}":
                return found
            key = json.loads(self._string()[0])
            self._skip_whitespace()
            self._pos += 1  # the colon
            self._skip_whitespace()
            value_start = self._pos
            self._skip_value(0)
            found.append(_Member(key, value_start, self._pos))
            self._skip_whitespace()
            if self._text[self._pos] == ",":
                self._pos += 1

    def string_content(self, start: int) -> tuple[int, int]:
        self._pos = start
        _, content = self._string()
        return content

    def _string(self) -> tuple[str, tuple[int, int]]:
        match = _STRING.match(self._text, self._pos)
        if match is None:
            raise FixUnsupportedError("manifest_invalid_json")
        self._pos = match.end()
        return match.group(0), (match.start(1), match.end(1))

    def _skip_whitespace(self) -> None:
        match = _WHITESPACE.match(self._text, self._pos)
        if match is not None:
            self._pos = match.end()

    def _skip_value(self, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise FixUnsupportedError("manifest_too_deep")
        opener = self._text[self._pos]
        if opener == '"':
            self._string()
        elif opener == "{":
            self._skip_container("}", depth, keyed=True)
        elif opener == "[":
            self._skip_container("]", depth, keyed=False)
        else:
            literal = _LITERAL.match(self._text, self._pos)
            if literal is None:
                raise FixUnsupportedError("manifest_invalid_json")
            self._pos = literal.end()

    def _skip_container(self, closer: str, depth: int, *, keyed: bool) -> None:
        self._pos += 1
        while True:
            self._skip_whitespace()
            if self._text[self._pos] == closer:
                self._pos += 1
                return
            if keyed:
                self._string()
                self._skip_whitespace()
                self._pos += 1  # the colon
                self._skip_whitespace()
            self._skip_value(depth + 1)
            self._skip_whitespace()
            if self._text[self._pos] == ",":
                self._pos += 1


def _declarations(text: str, package: str) -> list[_Declaration]:
    try:
        document = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise FixUnsupportedError("manifest_invalid_json") from error
    if not isinstance(document, dict):
        raise FixUnsupportedError("manifest_invalid_json")
    scanner = _Scanner(text)
    top = scanner.members(scanner.first_value())
    found: list[_Declaration] = []
    for section in DEPENDENCY_SECTIONS:
        sections = [member for member in top if member.key == section]
        if len(sections) > 1:
            # JSON readers keep the last duplicate; which one counts is a guess.
            raise FixUnsupportedError("manifest_duplicate_section")
        if not sections or text[sections[0].value_start] != "{":
            continue
        entries = [m for m in scanner.members(sections[0].value_start) if m.key == package]
        if len(entries) > 1:
            raise FixUnsupportedError("manifest_duplicate_declaration")
        if entries:
            entry = entries[0]
            if text[entry.value_start] != '"':
                found.append(_Declaration(section, entry.value_start, entry.value_end, None))
                continue
            start, end = scanner.string_content(entry.value_start)
            found.append(_Declaration(section, start, end, text[start:end]))
    return found


def plan_edits(text: str, package: str, fix_version: str) -> list[FixEdit]:
    """Plan the minimal spec edits that move ``package`` to ``fix_version``."""

    if _PLAIN_VERSION.match(fix_version) is None:
        raise FixUnsupportedError("fix_version_not_plain_semver")
    declarations = _declarations(text, package)
    if not declarations:
        raise FixUnsupportedError("not_declared")
    edits: list[FixEdit] = []
    for declaration in declarations:
        spec = declaration.spec
        if spec is None:
            raise FixUnsupportedError("spec_not_a_string")
        plain = _PLAIN_SPEC.match(spec)
        if plain is None:
            raise FixUnsupportedError(_unsupported_spec_reason(spec))
        if _version_key(plain.group("version")) >= _version_key(fix_version):
            # The declared range already allows the fix, so the manifest is not
            # what pins the vulnerable version; raising it would be a downgrade.
            continue
        edits.append(
            FixEdit(
                declaration.section,
                declaration.start,
                declaration.end,
                spec,
                plain.group("operator") + fix_version,
            )
        )
    if not edits:
        raise FixUnsupportedError("declared_range_already_covers_fix")
    return sorted(edits, key=lambda edit: edit.start)


def apply_edits(text: str, edits: list[FixEdit]) -> str:
    updated = text
    for edit in sorted(edits, key=lambda item: item.start, reverse=True):
        if updated[edit.start : edit.end] != edit.from_spec:
            raise FixUnsupportedError("manifest_changed")
        updated = updated[: edit.start] + edit.to_spec + updated[edit.end :]
    return updated


def unified_diff(before: str, after: str, relative_path: str) -> str:
    diff = "".join(
        difflib.unified_diff(_lines(before), _lines(after), fromfile=f"a/{relative_path}", tofile=f"b/{relative_path}")
    )
    if len(diff.encode("utf-8")) > MAX_FIX_DIFF_BYTES:
        raise FixUnsupportedError("diff_too_large")
    return diff


def _lines(text: str) -> list[str]:
    # Only "\n" ends a line here; str.splitlines would also split on form feeds
    # and Unicode separators that can legitimately sit inside a JSON string.
    parts = text.split("\n")
    return [part + "\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _unsupported_spec_reason(spec: str) -> str:
    lowered = spec.strip().lower()
    if lowered.startswith("workspace:"):
        return "spec_workspace_protocol"
    if lowered.startswith("npm:"):
        return "spec_npm_alias"
    if lowered.startswith(("file:", "link:", "portal:", ".", "/", "~/")):
        return "spec_local_path"
    if "://" in lowered or lowered.startswith(("git", "github:", "gitlab:", "bitbucket:", "http")):
        return "spec_git_or_url"
    if re.match(r"^[a-z][a-z0-9._-]*$", lowered):
        return "spec_dist_tag"
    return "spec_not_plain_semver"


__all__ = [
    "DEPENDENCY_SECTIONS",
    "FixEdit",
    "FixUnsupportedError",
    "apply_edits",
    "plan_edits",
    "unified_diff",
]
