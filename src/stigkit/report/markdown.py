"""Markdown summary, sized for a CI job summary or a PR comment.

GitHub Actions renders whatever is appended to ``$GITHUB_STEP_SUMMARY``, so this
puts the compliance posture on the run page itself. The point is that someone
reads it without downloading an artefact -- an attached report is a report
nobody opens.
"""

from __future__ import annotations

from collections.abc import Sequence

from stigkit.analyze import Delta, control_family_rollup, host_ranking, summarize
from stigkit.models import ScanResult

__all__ = ["delta_to_markdown", "to_markdown"]

_TICK = {True: "✅", False: "❌"}


def to_markdown(scans: Sequence[ScanResult], *, threshold_met: bool = True) -> str:
    """Render a compliance summary as Markdown."""
    all_findings = [f for scan in scans for f in scan.findings]
    summary = summarize(all_findings)

    lines = [
        f"## {_TICK[threshold_met]} STIG compliance summary",
        "",
        f"**Compliance score: {summary.compliance_score}%** "
        f"({summary.assessed} rules assessed across {len(scans)} host(s))",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Open findings | {summary.open_findings} |",
    ]
    for severity, count in summary.open_by_severity.items():
        lines.append(f"| &nbsp;&nbsp;{severity.category} | {count} |")
    lines.append(f"| Rules assessed | {summary.assessed} |")
    lines.append(f"| Not applicable | {summary.total - summary.assessed} |")
    lines.append("")

    families = control_family_rollup(all_findings)
    if families:
        lines += [
            "### Open findings by NIST 800-53 family",
            "",
            "| Family | Open |",
            "| --- | ---: |",
        ]
        lines += [f"| {family} | {count} |" for family, count in families.items()]
        lines.append("")

    rows = host_ranking(scans)
    if len(rows) > 1:
        lines += [
            "### Hosts, worst first",
            "",
            "| Host | Open | CAT I | CAT II | CAT III | Score |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
        lines += [
            f"| {r.host} | {r.open_findings} | {r.cat_i} | {r.cat_ii} | "
            f"{r.cat_iii} | {r.compliance_score}% |"
            for r in rows
        ]
        lines.append("")

    return "\n".join(lines)


def delta_to_markdown(diff: Delta) -> str:
    """Render a scan-over-scan comparison as Markdown."""
    lines = [
        "## STIG compliance delta",
        "",
        "| Change | Count |",
        "| --- | ---: |",
        f"| \U0001f195 New findings | {len(diff.new_findings)} |",
        f"| ✅ Resolved | {len(diff.resolved)} |",
        f"| ➡️ Still open | {len(diff.persisting)} |",
        f"| ❓ Disappeared (unexplained) | {len(diff.disappeared)} |",
        "",
    ]
    if diff.new_findings:
        lines += ["### New findings", "", "| Severity | Vuln ID | Host | Title |",
                  "| --- | --- | --- | --- |"]
        lines += [
            f"| {f.rule.severity.category} | {f.rule.display_id} | {f.host} | {f.rule.title} |"
            for f in diff.new_findings
        ]
        lines.append("")
    if diff.disappeared:
        lines += [
            "> **Disappeared findings are not resolved findings.** A rule present in the "
            "earlier scan and absent from the later one may have been fixed, or the "
            "benchmark/profile may have changed, or the scan may not have finished. "
            "Confirm before crediting remediation.",
            "",
        ]
    return "\n".join(lines)
