"""STIG Viewer checklist parsing (``.cklb``, the JSON format).

STIG Viewer 3 replaced the XML ``.ckl`` with ``.cklb``, a JSON document. A
checklist differs from a scan result in an important way: it carries the
*analyst's* determination and their comments, not just the scanner's verdict.
Those comments routinely hold the POA&M or ticket reference, so they are
preserved end to end rather than dropped at the parse boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

from stigkit.models import ComplianceStatus, Finding, Rule, ScanResult, Severity

__all__ = ["CklbParseError", "parse_cklb"]


class CklbParseError(Exception):
    """The file is not a readable CKLB checklist."""


# CKLB uses lower_snake_case; the legacy CKL used MixedCase. Both appear in the
# wild -- exports from older tooling, hand-edited files -- so both are accepted.
_STATUS_MAP: dict[str, ComplianceStatus] = {
    "open": ComplianceStatus.NON_COMPLIANT,
    "not_a_finding": ComplianceStatus.COMPLIANT,
    "notafinding": ComplianceStatus.COMPLIANT,
    "not_applicable": ComplianceStatus.NOT_APPLICABLE,
    "notapplicable": ComplianceStatus.NOT_APPLICABLE,
    "not_reviewed": ComplianceStatus.NOT_REVIEWED,
    "notreviewed": ComplianceStatus.NOT_REVIEWED,
}


def _normalise_status(raw: str) -> ComplianceStatus:
    """Map a checklist status token, defaulting to NOT_REVIEWED.

    An unrecognised status is treated as unreviewed, never as compliant. An
    unknown token means the tool does not understand the evidence, and the safe
    reading of "I don't understand this" is "nobody has answered yet".
    """
    return _STATUS_MAP.get(raw.strip().lower().replace(" ", "_"), ComplianceStatus.NOT_REVIEWED)


def parse_cklb(path: str | Path) -> ScanResult:
    """Read a ``.cklb`` checklist into a :class:`ScanResult`.

    A checklist may hold several STIGs against one host; rules from all of them
    are flattened into a single result, since the host is the unit an ISSO
    reports on.
    """
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CklbParseError(f"{path.name}: invalid JSON at line {exc.lineno}") from exc
    except OSError as exc:
        raise CklbParseError(f"{path}: {exc.strerror}") from exc

    if not isinstance(document, dict):
        raise CklbParseError(f"{path.name}: expected a JSON object at the top level")

    target = document.get("target_data") or {}
    host = (target.get("host_name") or "").strip()

    stigs = document.get("stigs") or []
    titles = [s.get("display_name") or s.get("stig_name") or "" for s in stigs]
    benchmark_title = "; ".join(t for t in titles if t)

    findings: list[Finding] = []
    for stig in stigs:
        for entry in stig.get("rules") or []:
            rule = Rule(
                rule_id=(entry.get("rule_id") or "").strip(),
                group_id=(entry.get("group_id") or "").strip(),
                stig_id=(entry.get("rule_version") or "").strip(),
                title=(entry.get("rule_title") or "").strip(),
                severity=Severity.parse(entry.get("severity")),
                ccis=tuple(c.strip() for c in (entry.get("ccis") or []) if c and c.strip()),
                check_text=(entry.get("check_content") or "").strip(),
                fix_text=(entry.get("fix_text") or "").strip(),
            )
            findings.append(
                Finding(
                    rule=rule,
                    status=_normalise_status(entry.get("status") or ""),
                    host=host,
                    comments=(entry.get("comments") or "").strip(),
                )
            )

    return ScanResult(
        host=host,
        findings=tuple(findings),
        benchmark_id=(stigs[0].get("stig_id", "") if stigs else ""),
        benchmark_title=benchmark_title,
        source=str(path),
    )
