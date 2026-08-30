"""Command-line interface.

Exit codes are the contract with CI, so they are deliberately narrow:

    0  the run succeeded and the gate passed
    1  the run succeeded and the gate FAILED (findings at or above --fail-on)
    2  the run did not complete (bad input, unreadable file, refused XML)

The distinction between 1 and 2 matters. A pipeline should block on 1 and page
someone on 2 -- "the scanner crashed" and "the system is non-compliant" call for
different humans, and collapsing them into a generic non-zero teaches everyone
to rerun the job until it goes green.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console

from stigkit import __version__
from stigkit.analyze import attribute_controls, delta, summarize
from stigkit.models import CciIndex, ScanResult, Severity
from stigkit.parsers.cci import DEFAULT_REVISION, parse_cci_list
from stigkit.parsers.cklb import CklbParseError, parse_cklb
from stigkit.parsers.xccdf import parse_results
from stigkit.parsers.xml import XmlParseError, XmlSecurityError
from stigkit.report.console import render_delta, render_report
from stigkit.report.csvout import to_csv
from stigkit.report.jsonout import to_json_report
from stigkit.report.markdown import delta_to_markdown, to_markdown
from stigkit.report.sarif import to_sarif

__all__ = ["main"]

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

SCAN_SUFFIXES = {".xml", ".xccdf", ".cklb", ".ckl"}

# --fail-on names the least severe category that still blocks. 'cat2' blocks on
# CAT I and CAT II but lets CAT III through, which is how most programs actually
# gate: stop the release for a real hole, track the paperwork findings.
_GATE_THRESHOLDS: dict[str, int] = {
    "cat1": Severity.CAT_I.rank,
    "cat2": Severity.CAT_II.rank,
    "cat3": Severity.CAT_III.rank,
    "any": Severity.UNKNOWN.rank,
}


class CliError(Exception):
    """A problem worth reporting to the operator rather than a traceback."""


def _discover(paths: Sequence[str]) -> list[Path]:
    """Expand files and directories into a sorted list of scan artefacts."""
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            found.extend(
                p for p in sorted(path.rglob("*")) if p.suffix.lower() in SCAN_SUFFIXES
            )
        elif path.is_file():
            found.append(path)
        else:
            raise CliError(f"no such file or directory: {path}")
    if not found:
        raise CliError(
            "no scan files found. Expected one of: " + ", ".join(sorted(SCAN_SUFFIXES))
        )
    return found


def _load_scan(path: Path) -> ScanResult:
    """Dispatch to the parser for *path* based on its extension."""
    try:
        if path.suffix.lower() in {".cklb", ".ckl"}:
            return parse_cklb(path)
        return parse_results(path)
    except (XmlSecurityError, XmlParseError, CklbParseError) as exc:
        raise CliError(str(exc)) from None


def _load_cci(path: str | None, revision: int) -> CciIndex:
    if not path:
        return CciIndex()
    try:
        return parse_cci_list(path, revision=revision)
    except (XmlSecurityError, XmlParseError) as exc:
        raise CliError(str(exc)) from None


def _gate_failed(scans: Sequence[ScanResult], fail_on: str) -> bool:
    """True when any open finding is at or above the configured threshold."""
    if fail_on == "none":
        return False
    threshold = _GATE_THRESHOLDS[fail_on]
    return any(
        f.status.is_open_finding and f.rule.severity.rank <= threshold
        for scan in scans
        for f in scan.findings
    )


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _cmd_scan(args: argparse.Namespace) -> int:
    index = _load_cci(args.cci_list, args.nist_revision)
    scans = [attribute_controls(_load_scan(p), index) for p in _discover(args.paths)]

    failed = _gate_failed(scans, args.fail_on)

    if args.format == "table":
        console = Console(file=open(args.output, "w") if args.output else None)  # noqa: SIM115
        render_report(scans, console)
    elif args.format == "json":
        _emit(json.dumps(to_json_report(scans), indent=2), args.output)
    elif args.format == "sarif":
        _emit(
            json.dumps(
                to_sarif(scans, include_not_reviewed=args.include_not_reviewed), indent=2
            ),
            args.output,
        )
    elif args.format == "csv":
        _emit(to_csv(scans, open_only=args.open_only), args.output)
    elif args.format == "markdown":
        _emit(to_markdown(scans, threshold_met=not failed), args.output)

    if failed:
        summary = summarize([f for scan in scans for f in scan.findings])
        print(
            f"stigkit: gate failed - {summary.open_findings} open finding(s), "
            f"{summary.cat_i} at CAT I (--fail-on {args.fail_on})",
            file=sys.stderr,
        )
        return EXIT_GATE_FAILED
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace) -> int:
    index = _load_cci(args.cci_list, args.nist_revision)
    before = [attribute_controls(_load_scan(p), index) for p in _discover([args.before])]
    after = [attribute_controls(_load_scan(p), index) for p in _discover([args.after])]
    diff = delta(before, after)

    if args.format == "markdown":
        _emit(delta_to_markdown(diff), args.output)
    elif args.format == "json":
        _emit(
            json.dumps(
                {
                    "newFindings": len(diff.new_findings),
                    "resolved": len(diff.resolved),
                    "persisting": len(diff.persisting),
                    "disappeared": len(diff.disappeared),
                    "new": [
                        {
                            "host": f.host,
                            "vulnId": f.rule.display_id,
                            "severity": f.rule.severity.category,
                            "title": f.rule.title,
                        }
                        for f in diff.new_findings
                    ],
                },
                indent=2,
            ),
            args.output,
        )
    else:
        render_delta(diff, Console(file=open(args.output, "w") if args.output else None))  # noqa: SIM115

    if args.fail_on_new and diff.new_findings:
        print(
            f"stigkit: gate failed - {len(diff.new_findings)} new finding(s) "
            f"since the baseline scan",
            file=sys.stderr,
        )
        return EXIT_GATE_FAILED
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigkit",
        description=(
            "Parse DISA STIG/SCAP results, map findings to NIST 800-53 controls, "
            "and gate a pipeline on the outcome."
        ),
    )
    parser.add_argument("--version", action="version", version=f"stigkit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--cci-list",
        metavar="PATH",
        help="DISA U_CCI_List.xml, for NIST 800-53 control attribution. "
        "Without it findings are reported without control IDs.",
    )
    common.add_argument(
        "--nist-revision",
        type=int,
        default=DEFAULT_REVISION,
        metavar="N",
        help=f"NIST SP 800-53 revision to resolve CCIs against (default: {DEFAULT_REVISION})",
    )
    common.add_argument("-o", "--output", metavar="PATH", help="write to PATH (default: stdout)")

    scan = sub.add_parser(
        "scan", parents=[common], help="report on one or more scan results"
    )
    scan.add_argument(
        "paths", nargs="+", metavar="PATH", help="scan files or directories to read"
    )
    scan.add_argument(
        "-f",
        "--format",
        choices=["table", "json", "csv", "sarif", "markdown"],
        default="table",
    )
    scan.add_argument(
        "--fail-on",
        choices=["none", "cat1", "cat2", "cat3", "any"],
        default="none",
        help="exit 1 when an open finding is at or above this category "
        "(default: none, report only)",
    )
    scan.add_argument(
        "--include-not-reviewed",
        action="store_true",
        help="SARIF only: also emit unreviewed rules as notes",
    )
    scan.add_argument(
        "--open-only", action="store_true", help="CSV only: omit passing and N/A rules"
    )
    scan.set_defaults(func=_cmd_scan)

    diff = sub.add_parser(
        "diff", parents=[common], help="compare a baseline scan against a later one"
    )
    diff.add_argument("before", metavar="BASELINE", help="earlier scan file or directory")
    diff.add_argument("after", metavar="CURRENT", help="later scan file or directory")
    diff.add_argument(
        "-f", "--format", choices=["table", "json", "markdown"], default="table"
    )
    diff.add_argument(
        "--fail-on-new",
        action="store_true",
        help="exit 1 if any finding is new since the baseline",
    )
    diff.set_defaults(func=_cmd_diff)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"stigkit: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
