"""Domain model for STIG/SCAP compliance data.

The types here are deliberately source-agnostic. An XCCDF results file and a
CKLB checklist describe the same underlying facts in different vocabularies;
both parsers normalise into these types so that everything downstream --
analysis, reporting, CI gating -- has exactly one vocabulary to reason about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

__all__ = [
    "CciIndex",
    "ComplianceStatus",
    "Finding",
    "Rule",
    "ScanResult",
    "Severity",
]


class Severity(Enum):
    """DISA severity category.

    DISA speaks in CAT I/II/III; XCCDF speaks in high/medium/low. They are the
    same three buckets, so the enum carries both spellings and lets either one
    parse. ``UNKNOWN`` exists because content in the wild does omit @severity,
    and silently defaulting that to "low" would understate risk -- the one
    direction a compliance tool must never round.
    """

    CAT_I = "high"
    CAT_II = "medium"
    CAT_III = "low"
    UNKNOWN = "unknown"

    @property
    def category(self) -> str:
        """DISA-facing label, e.g. ``CAT I``."""
        return {
            Severity.CAT_I: "CAT I",
            Severity.CAT_II: "CAT II",
            Severity.CAT_III: "CAT III",
            Severity.UNKNOWN: "unknown",
        }[self]

    @property
    def rank(self) -> int:
        """Sort key. Lower is more severe, so ``sorted()`` puts CAT I first."""
        return {
            Severity.CAT_I: 0,
            Severity.CAT_II: 1,
            Severity.CAT_III: 2,
            Severity.UNKNOWN: 3,
        }[self]

    @classmethod
    def parse(cls, raw: str | None) -> Severity:
        """Accept XCCDF (``high``), DISA (``CAT I``), or CKLB (``CAT_I``) spellings."""
        if not raw:
            return cls.UNKNOWN
        token = raw.strip().lower().replace("_", " ").replace("-", " ")
        token = " ".join(token.split())
        aliases = {
            "high": cls.CAT_I,
            "cat i": cls.CAT_I,
            "cat 1": cls.CAT_I,
            "i": cls.CAT_I,
            "medium": cls.CAT_II,
            "cat ii": cls.CAT_II,
            "cat 2": cls.CAT_II,
            "ii": cls.CAT_II,
            "low": cls.CAT_III,
            "cat iii": cls.CAT_III,
            "cat 3": cls.CAT_III,
            "iii": cls.CAT_III,
        }
        return aliases.get(token, cls.UNKNOWN)


class ComplianceStatus(Enum):
    """Normalised outcome for one rule on one host.

    Five buckets, because five is what you can actually act on:

    ``COMPLIANT``      the control is satisfied.
    ``NON_COMPLIANT``  an open finding; this is what a POA&M gets written for.
    ``NOT_APPLICABLE`` the rule does not apply to this host and is correctly
                       excluded from the denominator.
    ``NOT_REVIEWED``   nobody has answered the question yet. Distinct from
                       ``NOT_APPLICABLE`` on purpose: "not assessed" is a gap in
                       the assessment, "not applicable" is a completed judgement.
                       Collapsing the two is the classic way a dashboard reports
                       98% compliant on a system nobody has finished scanning.
    ``ERROR``          the check itself failed to execute. Also not a pass.
    """

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_REVIEWED = "not_reviewed"
    ERROR = "error"

    @property
    def is_open_finding(self) -> bool:
        """True when this status should be counted as an open finding."""
        return self in (ComplianceStatus.NON_COMPLIANT, ComplianceStatus.ERROR)

    @property
    def counts_toward_score(self) -> bool:
        """True when the status belongs in the compliance-percentage denominator.

        Not-applicable rules are excluded (they are not a question anyone owes
        an answer to). Not-reviewed rules are *included*, so an unfinished scan
        drags the score down instead of flattering it.
        """
        return self is not ComplianceStatus.NOT_APPLICABLE


@dataclass(frozen=True, slots=True)
class Rule:
    """One STIG requirement, as defined by a benchmark."""

    rule_id: str
    """XCCDF @id, e.g. ``SV-230221r991589_rule``."""

    group_id: str = ""
    """Vulnerability ID, e.g. ``V-230221``. DISA's stable human-facing handle."""

    stig_id: str = ""
    """Legacy/short STIG ID from ``version``, e.g. ``RHEL-09-211010``."""

    title: str = ""
    severity: Severity = Severity.UNKNOWN
    ccis: tuple[str, ...] = ()
    """CCI identifiers this rule satisfies, e.g. ``('CCI-000048',)``."""

    check_text: str = ""
    fix_text: str = ""

    @property
    def display_id(self) -> str:
        """Best available identifier for a human: V-ID, else STIG ID, else rule ID."""
        return self.group_id or self.stig_id or self.rule_id


@dataclass(frozen=True, slots=True)
class Finding:
    """The outcome of evaluating one :class:`Rule` against one host."""

    rule: Rule
    status: ComplianceStatus
    host: str = ""
    comments: str = ""
    controls: tuple[str, ...] = ()
    """NIST 800-53 control IDs, resolved from ``rule.ccis`` via :class:`CciIndex`.

    Empty until :func:`stigkit.analyze.attribute_controls` has run -- parsing and
    control attribution are separate steps so that a missing CCI list degrades
    the report rather than failing the parse.
    """

    @property
    def key(self) -> tuple[str, str]:
        """Identity of this finding across scans, for delta comparison."""
        return (self.host, self.rule.display_id)


@dataclass(frozen=True, slots=True)
class ScanResult:
    """One scan of one host against one benchmark."""

    host: str
    findings: tuple[Finding, ...]
    benchmark_id: str = ""
    benchmark_title: str = ""
    scanned_at: datetime | None = None
    source: str = ""
    """Path or filename the result came from; carried for report provenance."""


@dataclass(frozen=True, slots=True)
class CciIndex:
    """CCI -> NIST 800-53 control mapping, from DISA's public CCI list."""

    mapping: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def controls_for(self, ccis: tuple[str, ...]) -> tuple[str, ...]:
        """Resolve CCIs to a de-duplicated, sorted tuple of control IDs."""
        seen: set[str] = set()
        for cci in ccis:
            seen.update(self.mapping.get(cci, ()))
        return tuple(sorted(seen))

    def __bool__(self) -> bool:
        return bool(self.mapping)
