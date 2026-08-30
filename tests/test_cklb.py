from __future__ import annotations

from stigkit.models import ComplianceStatus, Severity
from stigkit.parsers.cklb import parse_cklb


class TestParseCklb:
    def test_reads_host_from_target_data(self, fixtures):
        scan = parse_cklb(fixtures / "checklist.cklb")
        assert scan.host == "demo-db-01"

    def test_normalises_cklb_status_vocabulary(self, fixtures):
        scan = parse_cklb(fixtures / "checklist.cklb")
        got = {f.rule.group_id: f.status for f in scan.findings}
        assert got == {
            "V-000001": ComplianceStatus.NON_COMPLIANT,   # open
            "V-000002": ComplianceStatus.COMPLIANT,       # not_a_finding
            "V-000003": ComplianceStatus.NOT_APPLICABLE,  # not_applicable
            "V-000004": ComplianceStatus.NOT_REVIEWED,    # not_reviewed
        }

    def test_carries_severity_and_ccis(self, fixtures):
        scan = parse_cklb(fixtures / "checklist.cklb")
        finding = next(f for f in scan.findings if f.rule.group_id == "V-000001")
        assert finding.rule.severity is Severity.CAT_I
        assert finding.rule.ccis == ("CCI-000048", "CCI-000050")

    def test_preserves_analyst_comments(self, fixtures):
        """Comments carry POA&M/ticket context and must survive into the report."""
        scan = parse_cklb(fixtures / "checklist.cklb")
        finding = next(f for f in scan.findings if f.rule.group_id == "V-000001")
        assert "DEMO-101" in finding.comments

    def test_benchmark_title_recorded(self, fixtures):
        scan = parse_cklb(fixtures / "checklist.cklb")
        assert "Synthetic Demo OS" in scan.benchmark_title
