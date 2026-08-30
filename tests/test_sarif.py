from __future__ import annotations

import json

from stigkit.models import ComplianceStatus, Finding, Rule, ScanResult, Severity
from stigkit.report.sarif import to_sarif


def _scan():
    return ScanResult(
        host="demo-web-01",
        source="results.xccdf.xml",
        benchmark_title="Synthetic Demo OS STIG",
        findings=(
            Finding(
                rule=Rule("SV-1", "V-000001", "DEMO-00-000010", "Banner missing",
                          Severity.CAT_I, ("CCI-000048",), fix_text="Configure the banner."),
                status=ComplianceStatus.NON_COMPLIANT,
                host="demo-web-01",
                controls=("AC-8",),
            ),
            Finding(
                rule=Rule("SV-2", "V-000002", "DEMO-00-000020", "Password length",
                          Severity.CAT_II),
                status=ComplianceStatus.COMPLIANT,
                host="demo-web-01",
            ),
            Finding(
                rule=Rule("SV-3", "V-000003", "DEMO-00-000030", "Timeout", Severity.CAT_III),
                status=ComplianceStatus.NON_COMPLIANT,
                host="demo-web-01",
            ),
        ),
    )


class TestSarifShape:
    def test_is_valid_sarif_210_envelope(self):
        doc = to_sarif([_scan()])
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert len(doc["runs"]) == 1

    def test_names_the_tool(self):
        driver = to_sarif([_scan()])["runs"][0]["tool"]["driver"]
        assert driver["name"] == "stigkit"
        assert "informationUri" in driver

    def test_only_open_findings_become_results(self):
        """Passing rules are not alerts."""
        results = to_sarif([_scan()])["runs"][0]["results"]
        assert [r["ruleId"] for r in results] == ["V-000001", "V-000003"]

    def test_severity_maps_to_sarif_level(self):
        results = to_sarif([_scan()])["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["V-000001"] == "error"   # CAT I
        assert levels["V-000003"] == "note"    # CAT III

    def test_every_result_indexes_a_declared_rule(self):
        run = to_sarif([_scan()])["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_results_carry_a_location(self):
        """GitHub Code Scanning drops results with no location."""
        for result in to_sarif([_scan()])["runs"][0]["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert uri

    def test_fingerprints_are_stable_across_runs(self):
        """Unstable fingerprints make GitHub reopen alerts that were dismissed."""
        a = to_sarif([_scan()])["runs"][0]["results"]
        b = to_sarif([_scan()])["runs"][0]["results"]
        assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]

    def test_fingerprint_differs_per_host(self):
        one = to_sarif([_scan()])["runs"][0]["results"][0]["partialFingerprints"]
        other_scan = ScanResult(
            host="demo-db-09",
            findings=tuple(
                Finding(f.rule, f.status, "demo-db-09", f.comments, f.controls)
                for f in _scan().findings
            ),
        )
        other = to_sarif([other_scan])["runs"][0]["results"][0]["partialFingerprints"]
        assert one != other

    def test_control_attribution_survives_into_properties(self):
        rules = to_sarif([_scan()])["runs"][0]["tool"]["driver"]["rules"]
        banner = next(r for r in rules if r["id"] == "V-000001")
        assert banner["properties"]["nist-800-53"] == ["AC-8"]
        assert "CAT I" in banner["properties"]["tags"]

    def test_message_names_the_host(self):
        result = to_sarif([_scan()])["runs"][0]["results"][0]
        assert "demo-web-01" in result["message"]["text"]

    def test_serialises_to_json(self):
        assert json.loads(json.dumps(to_sarif([_scan()])))
