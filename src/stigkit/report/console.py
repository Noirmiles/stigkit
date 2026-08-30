"""Terminal rendering.

Colour carries meaning here and nowhere else: CAT I is red because it blocks an
ATO, and if everything is coloured then nothing is. All output goes to the
``Console`` passed in so that tests capture it and ``--output`` can redirect it.
"""

from __future__ import annotations

from collections.abc import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from stigkit.analyze import Delta, control_family_rollup, host_ranking, summarize
from stigkit.models import ComplianceStatus, ScanResult, Severity

__all__ = ["render_delta", "render_report"]

_SEVERITY_STYLE = {
    Severity.CAT_I: "bold red",
    Severity.CAT_II: "yellow",
    Severity.CAT_III: "cyan",
    Severity.UNKNOWN: "dim",
}

_STATUS_STYLE = {
    ComplianceStatus.COMPLIANT: "green",
    ComplianceStatus.NON_COMPLIANT: "bold red",
    ComplianceStatus.ERROR: "bold magenta",
    ComplianceStatus.NOT_REVIEWED: "yellow",
    ComplianceStatus.NOT_APPLICABLE: "dim",
}


def _score_style(score: float) -> str:
    if score >= 90:
        return "bold green"
    if score >= 70:
        return "yellow"
    return "bold red"


def render_report(
    scans: Sequence[ScanResult],
    console: Console,
    *,
    max_findings: int = 25,
) -> None:
    """Print the compliance posture: headline, severity, families, hosts, findings."""
    all_findings = [f for scan in scans for f in scan.findings]
    summary = summarize(all_findings)

    console.print(
        Panel(
            f"[{_score_style(summary.compliance_score)}]"
            f"{summary.compliance_score}% compliant[/]  "
            f"[dim]({summary.assessed} rules assessed, "
            f"{summary.total - summary.assessed} N/A, "
            f"{len(scans)} host(s))[/]\n"
            f"[bold red]{summary.open_findings} open finding(s)[/]"
            f"  [dim]CAT I: {summary.cat_i}[/]",
            title="STIG compliance",
            border_style="blue",
        )
    )

    if summary.open_by_severity:
        table = Table(title="Open findings by severity", header_style="bold")
        table.add_column("Severity")
        table.add_column("Open", justify="right")
        for severity, count in summary.open_by_severity.items():
            table.add_row(
                f"[{_SEVERITY_STYLE[severity]}]{severity.category}[/]", str(count)
            )
        console.print(table)

    families = control_family_rollup(all_findings)
    if families:
        table = Table(title="Open findings by NIST 800-53 family", header_style="bold")
        table.add_column("Family")
        table.add_column("Open", justify="right")
        for family, count in families.items():
            table.add_row(family, str(count))
        console.print(table)

    rows = host_ranking(scans)
    if len(rows) > 1:
        table = Table(title="Hosts, worst first", header_style="bold")
        table.add_column("Host")
        table.add_column("Open", justify="right")
        table.add_column("CAT I", justify="right", style="red")
        table.add_column("CAT II", justify="right", style="yellow")
        table.add_column("CAT III", justify="right", style="cyan")
        table.add_column("Score", justify="right")
        for row in rows:
            table.add_row(
                row.host,
                str(row.open_findings),
                str(row.cat_i),
                str(row.cat_ii),
                str(row.cat_iii),
                f"[{_score_style(row.compliance_score)}]{row.compliance_score}%[/]",
            )
        console.print(table)

    open_findings = sorted(
        (f for f in all_findings if f.status.is_open_finding),
        key=lambda f: (f.rule.severity.rank, f.host, f.rule.display_id),
    )
    if not open_findings:
        console.print("[bold green]No open findings.[/]")
        return

    table = Table(title="Open findings", header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Vuln ID", no_wrap=True)
    table.add_column("Host", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("800-53", no_wrap=True)
    table.add_column("Title")
    for finding in open_findings[:max_findings]:
        table.add_row(
            f"[{_SEVERITY_STYLE[finding.rule.severity]}]{finding.rule.severity.category}[/]",
            finding.rule.display_id,
            finding.host,
            f"[{_STATUS_STYLE[finding.status]}]{finding.status.value}[/]",
            ", ".join(finding.controls) or "[dim]-[/]",
            finding.rule.title,
        )
    console.print(table)
    if len(open_findings) > max_findings:
        console.print(
            f"[dim]... and {len(open_findings) - max_findings} more. "
            f"Use --format csv or --format json for the full set.[/]"
        )


def render_delta(diff: Delta, console: Console) -> None:
    """Print a scan-over-scan comparison."""
    table = Table(title="Compliance delta", header_style="bold")
    table.add_column("Change")
    table.add_column("Count", justify="right")
    table.add_row("[bold red]New findings[/]", str(len(diff.new_findings)))
    table.add_row("[green]Resolved[/]", str(len(diff.resolved)))
    table.add_row("[yellow]Still open[/]", str(len(diff.persisting)))
    table.add_row("[magenta]Disappeared[/]", str(len(diff.disappeared)))
    console.print(table)

    if diff.new_findings:
        table = Table(title="New findings", header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Vuln ID", no_wrap=True)
        table.add_column("Host", no_wrap=True)
        table.add_column("Title")
        for f in diff.new_findings:
            table.add_row(
                f"[{_SEVERITY_STYLE[f.rule.severity]}]{f.rule.severity.category}[/]",
                f.rule.display_id,
                f.host,
                f.rule.title,
            )
        console.print(table)

    if diff.disappeared:
        console.print(
            Panel(
                "These findings were open in the earlier scan and are absent from the "
                "later one. That is [bold]not[/] evidence of remediation - the benchmark "
                "or profile may have changed, or the scan may not have completed. "
                "Confirm each before crediting it as fixed.",
                title=f"{len(diff.disappeared)} disappeared finding(s)",
                border_style="magenta",
            )
        )
