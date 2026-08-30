"""CLI behaviour, with the exit-code contract pinned.

The exit codes are what CI depends on, so they get explicit tests rather than
being an emergent property of whatever the last branch happened to return.
"""

from __future__ import annotations

import json

import pytest

from stigkit.cli import EXIT_ERROR, EXIT_GATE_FAILED, EXIT_OK, main


class TestExitCodes:
    def test_reporting_run_succeeds(self, fixtures):
        assert main(["scan", str(fixtures / "results.xccdf.xml")]) == EXIT_OK

    def test_gate_trips_on_cat_one(self, fixtures):
        code = main(["scan", str(fixtures / "results.xccdf.xml"), "--fail-on", "cat1"])
        assert code == EXIT_GATE_FAILED

    def test_gate_passes_when_threshold_is_below_findings(self, fixtures, tmp_path):
        """The checklist's only open finding is CAT I, so a CAT-III-only gate...

        ...still trips, because cat3 means "CAT III and above". This pins the
        direction of the threshold, which is the easy thing to invert.
        """
        code = main(["scan", str(fixtures / "checklist.cklb"), "--fail-on", "cat3"])
        assert code == EXIT_GATE_FAILED

    def test_no_gate_by_default(self, fixtures):
        assert main(["scan", str(fixtures / "checklist.cklb")]) == EXIT_OK

    def test_unreadable_input_is_exit_two_not_one(self, fixtures, capsys):
        """A broken run must be distinguishable from a failed gate."""
        code = main(["scan", str(fixtures / "does-not-exist.xml")])
        assert code == EXIT_ERROR

    def test_refused_xml_is_exit_two(self, fixtures):
        assert main(["scan", str(fixtures / "malicious_xxe.xml")]) == EXIT_ERROR


class TestOutputFormats:
    @pytest.mark.parametrize("fmt", ["table", "json", "csv", "sarif", "markdown"])
    def test_every_format_writes_output(self, fixtures, tmp_path, fmt):
        out = tmp_path / f"report.{fmt}"
        code = main([
            "scan", str(fixtures / "results.xccdf.xml"),
            "-f", fmt, "-o", str(out),
        ])
        assert code == EXIT_OK
        assert out.read_text().strip()

    def test_json_output_is_parseable_and_versioned(self, fixtures, tmp_path):
        out = tmp_path / "r.json"
        main(["scan", str(fixtures / "results.xccdf.xml"), "-f", "json", "-o", str(out)])
        doc = json.loads(out.read_text())
        assert doc["schemaVersion"] == 1
        assert doc["summary"]["openFindings"] == 2

    def test_sarif_output_is_parseable(self, fixtures, tmp_path):
        out = tmp_path / "r.sarif"
        main(["scan", str(fixtures / "results.xccdf.xml"), "-f", "sarif", "-o", str(out)])
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"

    def test_csv_open_only_filters(self, fixtures, tmp_path):
        full = tmp_path / "full.csv"
        partial = tmp_path / "open.csv"
        main(["scan", str(fixtures / "results.xccdf.xml"), "-f", "csv", "-o", str(full)])
        main([
            "scan", str(fixtures / "results.xccdf.xml"),
            "-f", "csv", "--open-only", "-o", str(partial),
        ])
        assert len(partial.read_text().splitlines()) < len(full.read_text().splitlines())


class TestControlAttribution:
    def test_cci_list_adds_control_ids(self, fixtures, tmp_path):
        out = tmp_path / "r.json"
        main([
            "scan", str(fixtures / "results.xccdf.xml"),
            "--cci-list", str(fixtures / "cci_list.xml"),
            "-f", "json", "-o", str(out),
        ])
        doc = json.loads(out.read_text())
        banner = next(f for f in doc["findings"] if f["vulnId"] == "V-000001")
        assert banner["controls"] == ["AC-8"]

    def test_runs_without_a_cci_list(self, fixtures, tmp_path):
        """Control attribution is optional; its absence must not fail the run."""
        out = tmp_path / "r.json"
        assert main([
            "scan", str(fixtures / "results.xccdf.xml"), "-f", "json", "-o", str(out),
        ]) == EXIT_OK
        doc = json.loads(out.read_text())
        assert all(f["controls"] == [] for f in doc["findings"])


class TestDiff:
    def test_reports_new_findings(self, fixtures, tmp_path):
        out = tmp_path / "d.json"
        code = main([
            "diff",
            str(fixtures / "checklist.cklb"),
            str(fixtures / "results.xccdf.xml"),
            "-f", "json", "-o", str(out),
        ])
        assert code == EXIT_OK
        assert "newFindings" in json.loads(out.read_text())

    def test_fail_on_new_trips_the_gate(self, fixtures, tmp_path):
        code = main([
            "diff",
            str(fixtures / "checklist.cklb"),
            str(fixtures / "results.xccdf.xml"),
            "--fail-on-new", "-f", "json", "-o", str(tmp_path / "d.json"),
        ])
        assert code == EXIT_GATE_FAILED


class TestDirectoryDiscovery:
    def test_reads_a_directory_of_scans(self, tmp_path, fixtures):
        import shutil

        scans = tmp_path / "scans"
        scans.mkdir()
        shutil.copy(fixtures / "checklist.cklb", scans / "a.cklb")
        shutil.copy(fixtures / "results.xccdf.xml", scans / "b.xml")
        out = tmp_path / "r.json"
        main(["scan", str(scans), "-f", "json", "-o", str(out)])
        doc = json.loads(out.read_text())
        assert doc["summary"]["hosts"] == 2

    def test_empty_directory_is_an_error(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert main(["scan", str(empty)]) == EXIT_ERROR
