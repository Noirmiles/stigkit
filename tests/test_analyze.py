from __future__ import annotations

from stigkit.analyze import (
    attribute_controls,
    control_family_rollup,
    delta,
    host_ranking,
    summarize,
)
from stigkit.models import ComplianceStatus, Finding, Rule, ScanResult, Severity
from stigkit.parsers.cci import parse_cci_list
from stigkit.parsers.xccdf import parse_results


def _finding(gid, status, sev=Severity.CAT_II, host="h1", ccis=()):
    return Finding(
        rule=Rule(rule_id=f"SV-{gid}", group_id=gid, severity=sev, ccis=ccis, title=gid),
        status=status,
        host=host,
    )


class TestSummarize:
    def test_counts_by_status(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        s = summarize(scan.findings)
        assert s.total == 5
        assert s.by_status[ComplianceStatus.NON_COMPLIANT] == 1
        assert s.by_status[ComplianceStatus.COMPLIANT] == 1
        assert s.by_status[ComplianceStatus.NOT_APPLICABLE] == 1

    def test_open_findings_include_errors(self, fixtures):
        """A check that errored is an open finding, not a pass."""
        scan = parse_results(fixtures / "results.xccdf.xml")
        assert summarize(scan.findings).open_findings == 2

    def test_score_excludes_not_applicable_from_denominator(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        # 5 rules, 1 N/A -> denominator 4, 1 compliant -> 25%
        assert summarize(scan.findings).compliance_score == 25.0

    def test_score_is_zero_safe_on_empty_input(self):
        assert summarize(()).compliance_score == 0.0

    def test_unreviewed_rules_drag_the_score_down(self):
        """The anti-flattery property: an unfinished scan must not read as clean."""
        done = [_finding("V-1", ComplianceStatus.COMPLIANT)]
        half = [
            _finding("V-1", ComplianceStatus.COMPLIANT),
            _finding("V-2", ComplianceStatus.NOT_REVIEWED),
        ]
        assert summarize(done).compliance_score == 100.0
        assert summarize(half).compliance_score == 50.0

    def test_open_by_severity_sorted_most_severe_first(self):
        findings = [
            _finding("V-1", ComplianceStatus.NON_COMPLIANT, Severity.CAT_III),
            _finding("V-2", ComplianceStatus.NON_COMPLIANT, Severity.CAT_I),
            _finding("V-3", ComplianceStatus.NON_COMPLIANT, Severity.CAT_II),
        ]
        assert list(summarize(findings).open_by_severity) == [
            Severity.CAT_I,
            Severity.CAT_II,
            Severity.CAT_III,
        ]


class TestAttributeControls:
    def test_resolves_ccis_to_controls(self, fixtures):
        scan = parse_results(fixtures / "results.xccdf.xml")
        index = parse_cci_list(fixtures / "cci_list.xml")
        attributed = attribute_controls(scan, index)
        first = next(f for f in attributed.findings if f.rule.group_id == "V-000001")
        assert first.controls == ("AC-8",)

    def test_unmapped_cci_degrades_instead_of_failing(self, fixtures):
        """An unknown CCI must leave controls empty, not raise."""
        scan = parse_results(fixtures / "results.xccdf.xml")
        index = parse_cci_list(fixtures / "cci_list.xml")
        attributed = attribute_controls(scan, index)
        assert all(isinstance(f.controls, tuple) for f in attributed.findings)

    def test_is_a_no_op_without_a_cci_list(self, fixtures):
        from stigkit.models import CciIndex

        scan = parse_results(fixtures / "results.xccdf.xml")
        attributed = attribute_controls(scan, CciIndex())
        assert all(f.controls == () for f in attributed.findings)


class TestControlFamilyRollup:
    def test_groups_open_findings_by_family(self):
        findings = [
            Finding(Rule("r1", "V-1"), ComplianceStatus.NON_COMPLIANT, controls=("AC-8",)),
            Finding(Rule("r2", "V-2"), ComplianceStatus.NON_COMPLIANT, controls=("AC-11",)),
            Finding(Rule("r3", "V-3"), ComplianceStatus.NON_COMPLIANT, controls=("AU-12",)),
            Finding(Rule("r4", "V-4"), ComplianceStatus.COMPLIANT, controls=("AC-2",)),
        ]
        assert control_family_rollup(findings) == {"AC": 2, "AU": 1}

    def test_finding_touching_two_families_counts_in_both(self):
        findings = [
            Finding(Rule("r1", "V-1"), ComplianceStatus.NON_COMPLIANT, controls=("AC-8", "AU-12")),
        ]
        assert control_family_rollup(findings) == {"AC": 1, "AU": 1}


class TestHostRanking:
    def test_ranks_hosts_by_open_finding_count(self):
        scans = [
            ScanResult("web-01", tuple(
                _finding(f"V-{i}", ComplianceStatus.NON_COMPLIANT, host="web-01") for i in range(3)
            )),
            ScanResult("db-01", tuple(
                _finding(f"V-{i}", ComplianceStatus.NON_COMPLIANT, host="db-01") for i in range(5)
            )),
        ]
        assert [row.host for row in host_ranking(scans)] == ["db-01", "web-01"]

    def test_ties_break_on_cat_one_count(self):
        scans = [
            ScanResult("a", (
                _finding("V-1", ComplianceStatus.NON_COMPLIANT, Severity.CAT_III, "a"),
                _finding("V-2", ComplianceStatus.NON_COMPLIANT, Severity.CAT_III, "a"),
            )),
            ScanResult("b", (
                _finding("V-1", ComplianceStatus.NON_COMPLIANT, Severity.CAT_I, "b"),
                _finding("V-2", ComplianceStatus.NON_COMPLIANT, Severity.CAT_III, "b"),
            )),
        ]
        assert [row.host for row in host_ranking(scans)] == ["b", "a"]


class TestDelta:
    def test_identifies_new_resolved_and_persisting(self):
        before = ScanResult("h1", (
            _finding("V-1", ComplianceStatus.NON_COMPLIANT),
            _finding("V-2", ComplianceStatus.NON_COMPLIANT),
            _finding("V-3", ComplianceStatus.COMPLIANT),
        ))
        after = ScanResult("h1", (
            _finding("V-1", ComplianceStatus.NON_COMPLIANT),   # persists
            _finding("V-2", ComplianceStatus.COMPLIANT),       # resolved
            _finding("V-3", ComplianceStatus.NON_COMPLIANT),   # new
        ))
        d = delta([before], [after])
        assert [f.rule.group_id for f in d.new_findings] == ["V-3"]
        assert [f.rule.group_id for f in d.resolved] == ["V-2"]
        assert [f.rule.group_id for f in d.persisting] == ["V-1"]

    def test_a_rule_that_vanished_is_not_reported_as_resolved(self):
        """Dropping a rule from scope is not the same as fixing it."""
        before = ScanResult("h1", (_finding("V-1", ComplianceStatus.NON_COMPLIANT),))
        after = ScanResult("h1", ())
        d = delta([before], [after])
        assert d.resolved == ()
        assert [f.rule.group_id for f in d.disappeared] == ["V-1"]
