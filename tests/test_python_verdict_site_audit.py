"""Every Python site that produces a Guard verdict stays audited.

See `docs/guard/audits/maj-ac-01-per-root-authority-audit.md`. A new site has to
be read and recorded in the baseline before it can land.
"""

from __future__ import annotations

import json

from tests.delivery_scripts import script

audit = script("audit_python_verdict_sites")


def _baseline() -> dict[str, object]:
    return json.loads(audit.BASELINE.read_text(encoding="utf-8"))


def test_discovered_verdict_sites_match_the_audit() -> None:
    found = {(str(site["file"]), str(site["func"])) for site in audit.discover()}
    recorded = {(str(site["file"]), str(site["func"])) for site in _baseline()["sites"]}
    assert found == recorded


def test_check_mode_passes_on_the_committed_baseline() -> None:
    assert audit.main(["--check"]) == 0


def test_every_audited_site_carries_a_reading() -> None:
    document = _baseline()
    readings = set(document["readings"])
    for site in document["sites"]:
        assert site["reading"] in readings, site["func"]
        assert str(site["note"]).strip(), site["func"]


def test_only_the_recorded_finding_composes_a_verdict_in_python() -> None:
    """The audit's one open finding. Removing it should remove this row."""

    composed = [site["func"] for site in _baseline()["sites"] if site["reading"] == "composes-in-python"]
    assert composed == ["native_package_review_response"]
