"""Machine-readable JSON output.

The stable contract for anything downstream -- a dashboard, a ticket-opener, an
eMASS import script. Report shape is versioned so a consumer can detect a
breaking change instead of silently misreading a renamed field.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from stigkit.analyze import control_family_rollup, host_ranking, summarize
from stigkit.models import ScanResult

__all__ = ["REPORT_SCHEMA_VERSION", "to_json_report"]

REPORT_SCHEMA_VERSION = 1


def _finding_dict(finding) -> dict[str, Any]:
    return {
        "host": finding.host,
        "vulnId": finding.rule.group_id,
        "stigId": finding.rule.stig_id,
        "ruleId": finding.rule.rule_id,
        "title": finding.rule.title,
        "severity": finding.rule.severity.category,
        "status": finding.status.value,
        "ccis": list(finding.rule.ccis),
        "controls": list(finding.controls),
        "comments": finding.comments,
    }


def to_json_report(scans: Sequence[ScanResult]) -> dict[str, Any]:
    """Full report: summary, per-host rollup, control families, every finding."""
    all_findings = [f for scan in scans for f in scan.findings]
    summary = summarize(all_findings)

    return {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "summary": {
            "hosts": len(scans),
            "totalRules": summary.total,
            "assessed": summary.assessed,
            "openFindings": summary.open_findings,
            "complianceScore": summary.compliance_score,
            "byStatus": {s.value: c for s, c in summary.by_status.items()},
            "openBySeverity": {s.category: c for s, c in summary.open_by_severity.items()},
        },
        "controlFamilies": control_family_rollup(all_findings),
        "hosts": [
            {
                "host": row.host,
                "openFindings": row.open_findings,
                "catI": row.cat_i,
                "catII": row.cat_ii,
                "catIII": row.cat_iii,
                "totalRules": row.total,
                "complianceScore": row.compliance_score,
            }
            for row in host_ranking(scans)
        ],
        "findings": [_finding_dict(f) for f in all_findings],
    }
