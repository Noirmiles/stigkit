"""Scoring, control attribution, ranking and scan-over-scan comparison.

Everything here is a pure function over parsed data. No I/O, no formatting --
which is what makes the compliance arithmetic straightforward to test, and the
arithmetic is the part that has to be right.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from stigkit.models import CciIndex, ComplianceStatus, Finding, ScanResult, Severity

__all__ = [
    "Delta",
    "HostRow",
    "Summary",
    "attribute_controls",
    "control_family_rollup",
    "delta",
    "host_ranking",
    "summarize",
]


@dataclass(frozen=True, slots=True)
class Summary:
    """Aggregate compliance posture over a set of findings."""

    total: int
    by_status: dict[ComplianceStatus, int]
    open_by_severity: dict[Severity, int]
    compliance_score: float

    @property
    def open_findings(self) -> int:
        """Non-compliant plus errored. See ``ComplianceStatus.is_open_finding``."""
        return sum(
            count for status, count in self.by_status.items() if status.is_open_finding
        )

    @property
    def cat_i(self) -> int:
        return self.open_by_severity.get(Severity.CAT_I, 0)

    @property
    def assessed(self) -> int:
        """Rules in the score denominator, i.e. everything not N/A."""
        return sum(
            count for status, count in self.by_status.items() if status.counts_toward_score
        )


def summarize(findings: Iterable[Finding]) -> Summary:
    """Compute the posture for *findings*.

    The compliance score is ``compliant / assessed``, where *assessed* excludes
    not-applicable rules and **includes** not-reviewed ones. That second half is
    the load-bearing decision: it means a half-finished scan reports as
    half-compliant rather than as compliant-so-far, so the number cannot be
    improved by simply not looking.
    """
    findings = list(findings)
    by_status = Counter(f.status for f in findings)

    open_counts = Counter(
        f.rule.severity for f in findings if f.status.is_open_finding
    )
    open_by_severity = {
        severity: open_counts[severity]
        for severity in sorted(open_counts, key=lambda s: s.rank)
    }

    assessed = sum(
        count for status, count in by_status.items() if status.counts_toward_score
    )
    compliant = by_status.get(ComplianceStatus.COMPLIANT, 0)
    score = round(100.0 * compliant / assessed, 2) if assessed else 0.0

    return Summary(
        total=len(findings),
        by_status=dict(by_status),
        open_by_severity=open_by_severity,
        compliance_score=score,
    )


def attribute_controls(scan: ScanResult, index: CciIndex) -> ScanResult:
    """Return *scan* with each finding's NIST 800-53 controls resolved.

    Kept separate from parsing so that a missing or unreadable CCI list degrades
    the report -- findings still appear, just without control attribution --
    rather than failing the run outright. Compliance tooling that refuses to
    tell you anything because one reference file is absent gets worked around,
    and a tool people work around is a tool nobody runs.
    """
    if not index:
        return scan
    attributed = tuple(
        Finding(
            rule=f.rule,
            status=f.status,
            host=f.host,
            comments=f.comments,
            controls=index.controls_for(f.rule.ccis),
        )
        for f in scan.findings
    )
    return ScanResult(
        host=scan.host,
        findings=attributed,
        benchmark_id=scan.benchmark_id,
        benchmark_title=scan.benchmark_title,
        scanned_at=scan.scanned_at,
        source=scan.source,
    )


def control_family_rollup(findings: Iterable[Finding]) -> dict[str, int]:
    """Count open findings per NIST 800-53 control family (``AC``, ``AU``, ...).

    A finding citing controls in two families counts once in each: the family is
    a view onto the finding, not a partition of it. Families with no open
    findings are omitted so the report shows problems, not an empty catalogue.
    """
    counts: Counter[str] = Counter()
    for finding in findings:
        if not finding.status.is_open_finding:
            continue
        families = {c.split("-", 1)[0] for c in finding.controls if "-" in c}
        counts.update(families)
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


@dataclass(frozen=True, slots=True)
class HostRow:
    """One host's line in the non-compliant leaderboard."""

    host: str
    open_findings: int
    cat_i: int
    cat_ii: int
    cat_iii: int
    total: int
    compliance_score: float


def host_ranking(scans: Sequence[ScanResult]) -> tuple[HostRow, ...]:
    """Rank hosts worst-first by open findings, breaking ties on CAT I count.

    Raw finding count alone ranks a host with forty CAT IIIs above one with a
    single unauthenticated-remote-access CAT I, which inverts the remediation
    order that actually matters. The tie-break puts severity back in charge.
    """
    rows: list[HostRow] = []
    for scan in scans:
        summary = summarize(scan.findings)
        rows.append(
            HostRow(
                host=scan.host or "(unnamed host)",
                open_findings=summary.open_findings,
                cat_i=summary.open_by_severity.get(Severity.CAT_I, 0),
                cat_ii=summary.open_by_severity.get(Severity.CAT_II, 0),
                cat_iii=summary.open_by_severity.get(Severity.CAT_III, 0),
                total=summary.total,
                compliance_score=summary.compliance_score,
            )
        )
    return tuple(
        sorted(rows, key=lambda r: (-r.open_findings, -r.cat_i, r.host))
    )


@dataclass(frozen=True, slots=True)
class Delta:
    """What changed between two scans."""

    new_findings: tuple[Finding, ...] = field(default=())
    resolved: tuple[Finding, ...] = field(default=())
    persisting: tuple[Finding, ...] = field(default=())
    disappeared: tuple[Finding, ...] = field(default=())
    """Open in the earlier scan and absent from the later one.

    Deliberately **not** counted as resolved. A rule can vanish because it was
    fixed, or because the benchmark was updated, the profile narrowed, or the
    scan did not finish. Only evidence of a pass proves remediation, so an
    absence is reported as its own category for someone to explain.
    """


def _index(scans: Iterable[ScanResult]) -> dict[tuple[str, str], Finding]:
    return {f.key: f for scan in scans for f in scan.findings}


def _ordered(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    return tuple(
        sorted(findings, key=lambda f: (f.rule.severity.rank, f.host, f.rule.display_id))
    )


def delta(
    before: Sequence[ScanResult],
    after: Sequence[ScanResult],
) -> Delta:
    """Compare two sets of scans, matching findings on ``(host, V-ID)``."""
    old = _index(before)
    new = _index(after)

    new_findings, resolved, persisting, disappeared = [], [], [], []

    for key, finding in new.items():
        was_open = key in old and old[key].status.is_open_finding
        if finding.status.is_open_finding:
            (persisting if was_open else new_findings).append(finding)
        elif was_open:
            resolved.append(finding)

    for key, finding in old.items():
        if key not in new and finding.status.is_open_finding:
            disappeared.append(finding)

    return Delta(
        new_findings=_ordered(new_findings),
        resolved=_ordered(resolved),
        persisting=_ordered(persisting),
        disappeared=_ordered(disappeared),
    )
