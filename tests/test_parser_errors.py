"""Failure paths. A compliance tool must fail loudly, never quietly."""

from __future__ import annotations

import pytest

from stigkit.models import CciIndex, Severity
from stigkit.parsers.cci import normalise_control_id, parse_cci_list
from stigkit.parsers.cklb import CklbParseError, parse_cklb
from stigkit.parsers.xccdf import parse_results
from stigkit.parsers.xml import XmlParseError, load_xml


class TestXmlErrors:
    def test_malformed_xml_raises(self, tmp_path):
        bad = tmp_path / "bad.xml"
        bad.write_text("<Benchmark><unclosed>")
        with pytest.raises(XmlParseError):
            load_xml(bad)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(XmlParseError):
            load_xml(tmp_path / "nope.xml")


class TestCklbErrors:
    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.cklb"
        bad.write_text("{not json")
        with pytest.raises(CklbParseError):
            parse_cklb(bad)

    def test_non_object_top_level_raises(self, tmp_path):
        bad = tmp_path / "list.cklb"
        bad.write_text("[]")
        with pytest.raises(CklbParseError):
            parse_cklb(bad)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(CklbParseError):
            parse_cklb(tmp_path / "nope.cklb")

    def test_unknown_status_becomes_not_reviewed_never_compliant(self, tmp_path):
        """The safe reading of an unrecognised status is 'nobody answered yet'."""
        doc = tmp_path / "odd.cklb"
        doc.write_text(
            '{"target_data":{"host_name":"h"},"stigs":[{"rules":['
            '{"group_id":"V-1","status":"banana"}]}]}'
        )
        from stigkit.models import ComplianceStatus

        scan = parse_cklb(doc)
        assert scan.findings[0].status is ComplianceStatus.NOT_REVIEWED


class TestXccdfEdgeCases:
    def test_results_file_with_no_testresult_yields_empty_scan(self, fixtures):
        scan = parse_results(fixtures / "benchmark.xccdf.xml")
        assert scan.findings == ()

    def test_orphan_rule_result_is_kept_not_dropped(self, tmp_path):
        """A result with no matching rule must still surface as a finding."""
        doc = tmp_path / "orphan.xml"
        doc.write_text(
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">'
            '<TestResult id="t"><target>h1</target>'
            '<rule-result idref="SV-ghost" severity="high"><result>fail</result>'
            "</rule-result></TestResult></Benchmark>"
        )
        scan = parse_results(doc)
        assert len(scan.findings) == 1
        assert scan.findings[0].rule.rule_id == "SV-ghost"
        assert scan.findings[0].rule.severity is Severity.CAT_I

    def test_unparseable_timestamp_is_none_not_a_crash(self, tmp_path):
        doc = tmp_path / "ts.xml"
        doc.write_text(
            '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">'
            '<TestResult id="t" end-time="not-a-date"><target>h1</target>'
            "</TestResult></Benchmark>"
        )
        assert parse_results(doc).scanned_at is None


class TestControlIdNormalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("AC-8 a", "AC-8"),
            ("IA-5 (1) (h)", "IA-5 (1)"),
            ("AU-12 c", "AU-12"),
            ("CM-6 b", "CM-6"),
            ("SC-28", "SC-28"),
            ("AC-02 (3)", "AC-2 (3)"),
            ("", ""),
            ("not a control", ""),
            ("Appendix F", ""),
        ],
    )
    def test_normalisation_cases(self, raw, expected):
        assert normalise_control_id(raw) == expected


class TestCciIndexBehaviour:
    def test_empty_index_is_falsey(self):
        assert not CciIndex()

    def test_cci_with_no_reference_for_revision_maps_to_nothing(self, fixtures):
        """CCI-000050 has only a Rev 5 reference."""
        rev4 = parse_cci_list(fixtures / "cci_list.xml", revision=4)
        assert "CCI-000050" not in rev4.mapping
