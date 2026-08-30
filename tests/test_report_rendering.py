"""Rendering tests.

These assert on *content*, not layout. Pinning exact table borders makes the
suite break every time a column widens, which trains people to regenerate
expectations without reading them.
"""

from __future__ import annotations

import io

from rich.console import Console

from stigkit.analyze import delta
from stigkit.models import ComplianceStatus, Finding, Rule, ScanResult, Severity
from stigkit.report.console import render_delta, render_report
from stigkit.report.csvout import COLUMNS, to_csv
from stigkit.report.markdown import delta_to_markdown, to_markdown


def _render(fn, *args) -> str:
    """Render to text with whitespace collapsed.

    rich wraps a narrow table's title across several lines, so asserting on a
    raw substring couples the test to column widths. Collapsing whitespace lets
    the assertions describe content and stay quiet about layout.
    """
    buffer = io.StringIO()
    fn(*args, Console(file=buffer, width=200, no_color=True))
    return " ".join(buffer.getvalue().split())


def _f(gid, status, sev=Severity.CAT_I, host="h1", controls=()):
    return Finding(
        rule=Rule(f"SV-{gid}", gid, f"DEMO-{gid}", f"title {gid}", sev),
        status=status,
        host=host,
        controls=controls,
    )


class TestConsoleReport:
    def test_shows_score_and_open_count(self):
        scan = ScanResult("h1", (
            _f("V-1", ComplianceStatus.NON_COMPLIANT),
            _f("V-2", ComplianceStatus.COMPLIANT),
        ))
        out = _render(render_report, [scan])
        assert "50.0% compliant" in out
        assert "1 open finding" in out
        assert "V-1" in out

    def test_says_so_when_there_is_nothing_open(self):
        scan = ScanResult("h1", (_f("V-1", ComplianceStatus.COMPLIANT),))
        assert "No open findings" in _render(render_report, [scan])

    def test_renders_host_leaderboard_for_multiple_hosts(self):
        scans = [
            ScanResult("web-01", (_f("V-1", ComplianceStatus.NON_COMPLIANT, host="web-01"),)),
            ScanResult("db-01", (_f("V-1", ComplianceStatus.COMPLIANT, host="db-01"),)),
        ]
        out = _render(render_report, scans)
        assert "Hosts, worst first" in out
        assert "web-01" in out and "db-01" in out

    def test_renders_control_family_rollup(self):
        scan = ScanResult("h1", (
            _f("V-1", ComplianceStatus.NON_COMPLIANT, controls=("AC-8",)),
        ))
        out = _render(render_report, [scan])
        assert "NIST 800-53 family" in out
        assert "AC" in out

    def test_truncates_a_long_finding_list(self):
        scan = ScanResult("h1", tuple(
            _f(f"V-{i}", ComplianceStatus.NON_COMPLIANT) for i in range(40)
        ))
        out = _render(render_report, [scan])
        assert "and 15 more" in out


class TestConsoleDelta:
    def test_reports_each_change_category(self):
        before = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        after = ScanResult("h1", (_f("V-1", ComplianceStatus.COMPLIANT),))
        out = _render(render_delta, delta([before], [after]))
        assert "Resolved" in out

    def test_warns_loudly_about_disappeared_findings(self):
        before = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        after = ScanResult("h1", ())
        out = _render(render_delta, delta([before], [after]))
        assert "not evidence of remediation" in out


class TestMarkdown:
    def test_headline_reflects_gate_outcome(self):
        scan = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        assert "❌" in to_markdown([scan], threshold_met=False)
        assert "✅" in to_markdown([scan], threshold_met=True)

    def test_includes_severity_breakdown(self):
        scan = ScanResult("h1", (
            _f("V-1", ComplianceStatus.NON_COMPLIANT, Severity.CAT_I),
            _f("V-2", ComplianceStatus.NON_COMPLIANT, Severity.CAT_III),
        ))
        out = to_markdown([scan])
        assert "CAT I" in out and "CAT III" in out

    def test_includes_control_families_when_attributed(self):
        scan = ScanResult("h1", (
            _f("V-1", ComplianceStatus.NON_COMPLIANT, controls=("AU-12",)),
        ))
        assert "AU" in to_markdown([scan])

    def test_host_table_only_appears_for_multiple_hosts(self):
        one = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        assert "Hosts, worst first" not in to_markdown([one])
        two = ScanResult("h2", (_f("V-1", ComplianceStatus.NON_COMPLIANT, host="h2"),))
        assert "Hosts, worst first" in to_markdown([one, two])

    def test_delta_markdown_lists_new_findings(self):
        before = ScanResult("h1", ())
        after = ScanResult("h1", (_f("V-9", ComplianceStatus.NON_COMPLIANT),))
        out = delta_to_markdown(delta([before], [after]))
        assert "New findings" in out and "V-9" in out

    def test_delta_markdown_explains_disappeared(self):
        before = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        after = ScanResult("h1", ())
        out = delta_to_markdown(delta([before], [after]))
        assert "not resolved findings" in out


class TestCsv:
    def test_header_matches_declared_columns(self):
        scan = ScanResult("h1", (_f("V-1", ComplianceStatus.NON_COMPLIANT),))
        assert to_csv([scan]).splitlines()[0] == ",".join(COLUMNS)

    def test_open_only_drops_passing_rules(self):
        scan = ScanResult("h1", (
            _f("V-1", ComplianceStatus.NON_COMPLIANT),
            _f("V-2", ComplianceStatus.COMPLIANT),
        ))
        assert len(to_csv([scan], open_only=True).strip().splitlines()) == 2
