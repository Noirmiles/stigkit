"""Flat CSV of findings -- the format that survives contact with a spreadsheet.

Deliberately one row per finding with no merged cells or section headers. This
is what gets pasted into a POA&M tracker or pivoted in Excel, and anything
prettier breaks that.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence

from stigkit.models import ScanResult

__all__ = ["COLUMNS", "to_csv"]

COLUMNS = [
    "host",
    "vuln_id",
    "stig_id",
    "rule_id",
    "severity",
    "status",
    "title",
    "ccis",
    "nist_800_53",
    "comments",
]


def to_csv(scans: Sequence[ScanResult], *, open_only: bool = False) -> str:
    """Render findings as CSV text."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for scan in scans:
        for f in scan.findings:
            if open_only and not f.status.is_open_finding:
                continue
            writer.writerow(
                [
                    f.host,
                    f.rule.group_id,
                    f.rule.stig_id,
                    f.rule.rule_id,
                    f.rule.severity.category,
                    f.status.value,
                    f.rule.title,
                    " ".join(f.rule.ccis),
                    " ".join(f.controls),
                    f.comments,
                ]
            )
    return buffer.getvalue()
