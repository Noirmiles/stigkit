"""SARIF 2.1.0 output -- the bridge from compliance data into DevSecOps tooling.

SARIF (OASIS Static Analysis Results Interchange Format) is what GitHub Code
Scanning, Azure DevOps and most modern security dashboards ingest. Emitting it
means STIG findings land in the same Security tab as Semgrep, Trivy and CodeQL
results, get the same triage and dismissal workflow, and can block a pull
request through the same branch-protection rule.

That is the whole argument for this module: a compliance finding nobody sees
until the monthly report is not a control, it is a document. A compliance
finding that appears on the pull request that caused it is a control.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from stigkit import __version__
from stigkit.models import Finding, ScanResult, Severity

__all__ = ["to_sarif"]

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/Noirmiles/stigkit"

# SARIF has three actionable levels plus "none". DISA has three categories.
# CAT I is an error because it is the category that blocks an ATO; CAT III is a
# note because paging someone at 2am over a session-timeout finding is how
# people learn to ignore the dashboard.
_LEVELS: dict[Severity, str] = {
    Severity.CAT_I: "error",
    Severity.CAT_II: "warning",
    Severity.CAT_III: "note",
    Severity.UNKNOWN: "warning",
}


def _fingerprint(finding: Finding) -> str:
    """Stable identity for a finding across runs.

    GitHub uses ``partialFingerprints`` to decide whether an alert in today's
    upload is the same alert as yesterday's. Derive it from anything volatile --
    a timestamp, a file path, a list index -- and every scan closes the old
    alerts and opens identical new ones, destroying the triage history and any
    dismissal an analyst recorded. Host plus V-ID is the pair that identifies
    the finding and nothing else.
    """
    material = f"{finding.host}\x00{finding.rule.display_id}".encode()
    return hashlib.sha256(material).hexdigest()[:32]


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    """SARIF reportingDescriptor for one STIG rule."""
    rule = finding.rule
    tags = ["stig", "compliance", rule.severity.category]
    tags.extend(f"nist-800-53/{c}" for c in finding.controls)

    descriptor: dict[str, Any] = {
        "id": rule.display_id,
        "name": rule.stig_id or rule.display_id,
        "shortDescription": {"text": rule.title or rule.display_id},
        "defaultConfiguration": {"level": _LEVELS[rule.severity]},
        "properties": {
            "severity": rule.severity.category,
            "stigId": rule.stig_id,
            "ruleId": rule.rule_id,
            "ccis": list(rule.ccis),
            "nist-800-53": list(finding.controls),
            "tags": tags,
        },
    }
    if rule.check_text:
        descriptor["fullDescription"] = {"text": rule.check_text}
    if rule.fix_text:
        descriptor["help"] = {
            "text": rule.fix_text,
            "markdown": f"**Fix**\n\n{rule.fix_text}",
        }
    return descriptor


def _message(finding: Finding) -> str:
    rule = finding.rule
    parts = [
        f"{rule.severity.category} {rule.display_id} is {finding.status.value.replace('_', ' ')}",
        f"on {finding.host or 'an unnamed host'}",
    ]
    if rule.title:
        parts.append(f"- {rule.title}")
    if finding.controls:
        parts.append(f"(NIST 800-53: {', '.join(finding.controls)})")
    return " ".join(parts)


def to_sarif(
    scans: Sequence[ScanResult],
    *,
    include_not_reviewed: bool = False,
) -> dict[str, Any]:
    """Render scans as a SARIF 2.1.0 document.

    Args:
        scans: parsed results, ideally after ``attribute_controls``.
        include_not_reviewed: also emit unreviewed rules as ``note`` results.
            Off by default -- an unreviewed rule is a gap in the assessment, not
            a defect in the system, and mixing the two trains people to ignore
            the queue. Turn it on when you are chasing scan coverage rather than
            remediation.

    Rules are declared once in ``tool.driver.rules`` and referenced by index, per
    the SARIF spec, so a finding repeated across two hundred hosts does not
    repeat its check and fix text two hundred times.
    """
    descriptors: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for scan in scans:
        for finding in scan.findings:
            reportable = finding.status.is_open_finding or (
                include_not_reviewed and finding.status.name == "NOT_REVIEWED"
            )
            if not reportable:
                continue

            key = finding.rule.display_id
            if key not in rule_index:
                rule_index[key] = len(descriptors)
                descriptors.append(_rule_descriptor(finding))

            results.append(
                {
                    "ruleId": key,
                    "ruleIndex": rule_index[key],
                    "level": _LEVELS[finding.rule.severity],
                    "message": {"text": _message(finding)},
                    "locations": [
                        {
                            "physicalLocation": {
                                # STIG findings describe a host, not a source
                                # line. Anchoring to the scan artefact keeps the
                                # result renderable -- Code Scanning discards
                                # results with no location at all.
                                "artifactLocation": {
                                    "uri": scan.source or f"scan/{scan.host or 'unknown'}",
                                },
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "partialFingerprints": {"stigkitFindingId/v1": _fingerprint(finding)},
                    "properties": {
                        "host": finding.host,
                        "status": finding.status.value,
                        "benchmark": scan.benchmark_title,
                    },
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "stigkit",
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": descriptors,
                    }
                },
                "results": results,
            }
        ],
    }
