"""XCCDF benchmark and results parsing.

A DISA STIG release is an XCCDF *Benchmark*: the rule catalogue. A scanner
(SCC, OpenSCAP, Evaluate-STIG) emits an XCCDF *TestResult*: one ``rule-result``
per rule, carrying only an ``idref`` and a verdict. Neither is useful alone --
the result says ``fail`` but not what failed; the benchmark says what the rule
is but not whether it passed. :func:`parse_results` joins them.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from stigkit.models import ComplianceStatus, Finding, Rule, ScanResult, Severity
from stigkit.parsers.xml import (
    find_local,
    findall_local,
    iter_local,
    load_xml,
    text_of,
)

__all__ = ["parse_benchmark", "parse_results"]

# XCCDF 1.2 defines nine result verbs. Mapping them onto five compliance states
# is where a compliance tool either earns trust or quietly lies:
#
#   notselected  the rule was excluded from the profile, so nobody owes an
#                answer -- genuinely not applicable.
#   notchecked   the rule was in scope and was not evaluated. That is an
#                incomplete assessment, NOT a pass.
#   informational  the check ran and declined to render a verdict.
#   unknown/error the check could not complete. Treated as an open finding,
#                because "the scanner broke" is not evidence of compliance.
_RESULT_MAP: dict[str, ComplianceStatus] = {
    "pass": ComplianceStatus.COMPLIANT,
    "fixed": ComplianceStatus.COMPLIANT,
    "fail": ComplianceStatus.NON_COMPLIANT,
    "notapplicable": ComplianceStatus.NOT_APPLICABLE,
    "notselected": ComplianceStatus.NOT_APPLICABLE,
    "notchecked": ComplianceStatus.NOT_REVIEWED,
    "informational": ComplianceStatus.NOT_REVIEWED,
    "unknown": ComplianceStatus.ERROR,
    "error": ComplianceStatus.ERROR,
}

_CCI_PREFIX = "CCI-"


def _rule_from_element(elem) -> Rule:
    """Build a :class:`Rule` from an XCCDF ``<Rule>`` element."""
    ccis = tuple(
        text.strip()
        for ident in findall_local(elem, "ident")
        if (text := (ident.text or "")).strip().upper().startswith(_CCI_PREFIX)
    )

    check_text = ""
    check = find_local(elem, "check")
    if check is not None:
        check_text = text_of(find_local(check, "check-content"))

    return Rule(
        rule_id=elem.get("id", ""),
        group_id="",  # filled in by the caller, which knows the parent Group
        stig_id=text_of(find_local(elem, "version")),
        title=text_of(find_local(elem, "title")),
        severity=Severity.parse(elem.get("severity")),
        ccis=ccis,
        check_text=check_text,
        fix_text=text_of(find_local(elem, "fixtext")),
    )


def parse_benchmark(path: str | Path) -> tuple[Rule, ...]:
    """Read every ``<Rule>`` in an XCCDF document.

    Works on a benchmark or on a results file that embeds its benchmark, and on
    both XCCDF 1.1 and 1.2 (matching is namespace-agnostic).

    The V-ID lives on the enclosing ``<Group>``, not the ``<Rule>``, so rules are
    collected by walking groups first and only then falling back to a flat scan
    for the rare benchmark that omits grouping.
    """
    root = load_xml(path)
    rules: list[Rule] = []
    claimed: set[int] = set()

    for group in iter_local(root, "Group"):
        group_id = group.get("id", "")
        for rule_elem in findall_local(group, "Rule"):
            claimed.add(id(rule_elem))
            rule = _rule_from_element(rule_elem)
            rules.append(
                Rule(
                    rule_id=rule.rule_id,
                    group_id=group_id,
                    stig_id=rule.stig_id,
                    title=rule.title,
                    severity=rule.severity,
                    ccis=rule.ccis,
                    check_text=rule.check_text,
                    fix_text=rule.fix_text,
                )
            )

    for rule_elem in iter_local(root, "Rule"):
        if id(rule_elem) not in claimed:
            rules.append(_rule_from_element(rule_elem))

    return tuple(rules)


def _parse_timestamp(result_elem) -> datetime | None:
    """Prefer ``end-time`` -- when the scan finished is when it was true."""
    for attr in ("end-time", "start-time"):
        raw = result_elem.get(attr)
        if not raw:
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def parse_results(
    path: str | Path,
    rules: tuple[Rule, ...] | None = None,
) -> ScanResult:
    """Read an XCCDF ``<TestResult>`` and join it against rule metadata.

    Args:
        path: results document. May embed its own benchmark.
        rules: catalogue to join against. When ``None``, rules are taken from the
            results document itself. Pass this explicitly for scanners that emit
            a bare ``<TestResult>`` with no benchmark alongside it.

    A ``rule-result`` with no matching rule still produces a Finding -- carrying
    the bare idref -- rather than being dropped. Silently discarding results you
    cannot explain is how findings go missing.
    """
    path = Path(path)
    root = load_xml(path)

    catalogue = rules if rules is not None else parse_benchmark(path)
    by_rule_id = {r.rule_id: r for r in catalogue if r.rule_id}

    result_elem = next(iter_local(root, "TestResult"), None)
    if result_elem is None:
        return ScanResult(host="", findings=(), source=str(path))

    target = find_local(result_elem, "target")
    host = text_of(target) if target is not None else ""

    benchmark_title = ""
    title_elem = find_local(root, "title")
    if title_elem is not None:
        benchmark_title = text_of(title_elem)

    findings: list[Finding] = []
    for rr in findall_local(result_elem, "rule-result"):
        idref = rr.get("idref", "")
        verdict = text_of(find_local(rr, "result")).lower()
        rule = by_rule_id.get(idref) or Rule(
            rule_id=idref, severity=Severity.parse(rr.get("severity"))
        )
        findings.append(
            Finding(
                rule=rule,
                status=_RESULT_MAP.get(verdict, ComplianceStatus.NOT_REVIEWED),
                host=host,
            )
        )

    return ScanResult(
        host=host,
        findings=tuple(findings),
        benchmark_id=root.get("id", ""),
        benchmark_title=benchmark_title,
        scanned_at=_parse_timestamp(result_elem),
        source=str(path),
    )
