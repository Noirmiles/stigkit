from __future__ import annotations

from stigkit.models import ComplianceStatus, Severity
from stigkit.parsers.xccdf import parse_benchmark, parse_results


class TestParseBenchmark:
    def test_reads_every_rule(self, fixtures):
        rules = parse_benchmark(fixtures / "benchmark.xccdf.xml")
        assert len(rules) == 5

    def test_extracts_identifiers(self, fixtures):
        rules = {r.group_id: r for r in parse_benchmark(fixtures / "benchmark.xccdf.xml")}
        rule = rules["V-000001"]
        assert rule.rule_id == "SV-000001r1_rule"
        assert rule.stig_id == "DEMO-00-000010"
        assert rule.title.startswith("The demo OS must display a logon banner")

    def test_maps_disa_severity(self, fixtures):
        rules = {r.group_id: r for r in parse_benchmark(fixtures / "benchmark.xccdf.xml")}
        assert rules["V-000001"].severity is Severity.CAT_I
        assert rules["V-000002"].severity is Severity.CAT_II
        assert rules["V-000003"].severity is Severity.CAT_III

    def test_missing_severity_is_unknown_not_low(self, fixtures):
        """Absent @severity must never be rounded down to CAT III."""
        rules = {r.group_id: r for r in parse_benchmark(fixtures / "benchmark.xccdf.xml")}
        assert rules["V-000004"].severity is Severity.UNKNOWN

    def test_collects_multiple_ccis(self, fixtures):
        rules = {r.group_id: r for r in parse_benchmark(fixtures / "benchmark.xccdf.xml")}
        assert rules["V-000001"].ccis == ("CCI-000048", "CCI-000050")

    def test_captures_check_and_fix_text(self, fixtures):
        rules = {r.group_id: r for r in parse_benchmark(fixtures / "benchmark.xccdf.xml")}
        assert "Verify a banner is configured" in rules["V-000001"].check_text
        assert "Configure the banner text" in rules["V-000001"].fix_text


class TestParseResults:
    def test_reads_target_hostname(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        assert scan.host == "demo-web-01"

    def test_normalises_every_xccdf_result_verb(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        got = {f.rule.group_id: f.status for f in scan.findings}
        assert got == {
            "V-000001": ComplianceStatus.NON_COMPLIANT,   # fail
            "V-000002": ComplianceStatus.COMPLIANT,       # pass
            "V-000003": ComplianceStatus.NOT_APPLICABLE,  # notapplicable
            "V-000004": ComplianceStatus.NOT_REVIEWED,    # notchecked
            "V-000005": ComplianceStatus.ERROR,           # error
        }

    def test_joins_results_to_rule_metadata(self, fixtures):
        """A rule-result carries only an idref; titles must come from the Rule."""
        scan = parse_results(fixtures / "results.xccdf.xml")
        finding = next(f for f in scan.findings if f.rule.group_id == "V-000001")
        assert finding.rule.severity is Severity.CAT_I
        assert "logon banner" in finding.rule.title

    def test_reads_scan_timestamp(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        assert scan.scanned_at is not None
        assert scan.scanned_at.year == 2026

    def test_handles_both_xccdf_namespaces(self, fixtures):
        """Benchmark fixture is XCCDF 1.1, results fixture is 1.2."""
        assert parse_benchmark(fixtures / "benchmark.xccdf.xml")
        assert parse_benchmark(fixtures / "results.xccdf.xml")
