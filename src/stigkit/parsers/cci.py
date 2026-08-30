"""DISA CCI list -> NIST 800-53 control mapping.

A STIG rule cites CCIs (Control Correlation Identifiers). A CCI is DISA's
atomic, testable restatement of one clause of one NIST 800-53 control. The CCI
list is the join table between "this host failed rule SV-000001" and "this
system has an open finding against AC-8", which is the only form an ISSO,
an eMASS record, or a program manager can act on.

DISA publishes the list at https://public.cyber.mil/stigs/cci/ as
``U_CCI_List.xml``. It is public, unclassified, and freely redistributable.
"""

from __future__ import annotations

import re
from pathlib import Path

from stigkit.models import CciIndex
from stigkit.parsers.xml import iter_local, load_xml

__all__ = ["DEFAULT_REVISION", "normalise_control_id", "parse_cci_list"]

DEFAULT_REVISION = 5
"""NIST SP 800-53 revision to resolve against. Rev 5 superseded Rev 4 in 2023."""

# 'AC-8 a'         -> family AC, number 8,  no enhancement
# 'IA-5 (1) (h)'   -> family IA, number 5,  enhancement 1
# 'AU-12 c'        -> family AU, number 12, no enhancement
_CONTROL_RE = re.compile(
    r"^\s*(?P<family>[A-Z]{2})-(?P<number>\d+)\s*(?:\(\s*(?P<enhancement>\d+)\s*\))?"
)


def normalise_control_id(index: str) -> str:
    """Reduce a CCI reference index to a canonical control ID.

    The reference index points at a *clause*: ``AC-8 a`` is paragraph (a) of
    AC-8. Reporting at clause granularity produces a control list nobody can
    reconcile against eMASS, so the trailing part letter is dropped and the
    control enhancement -- which *is* a separately assessed control -- is kept.

        ``AC-8 a``       -> ``AC-8``
        ``IA-5 (1) (h)`` -> ``IA-5 (1)``

    Returns an empty string for anything that is not a control reference.
    """
    match = _CONTROL_RE.match(index or "")
    if not match:
        return ""
    base = f"{match['family']}-{int(match['number'])}"
    if match["enhancement"]:
        return f"{base} ({int(match['enhancement'])})"
    return base


def _matches_revision(reference, revision: int) -> bool:
    """True when a ``<reference>`` belongs to the requested 800-53 revision.

    The version attribute is authoritative when present; the title is the
    fallback, because older list releases populate one but not the other.
    """
    version = (reference.get("version") or "").strip()
    if version:
        return version == str(revision)
    title = (reference.get("title") or "").lower()
    return f"revision {revision}" in title


def parse_cci_list(
    path: str | Path,
    revision: int = DEFAULT_REVISION,
) -> CciIndex:
    """Build a CCI -> control-ID index from DISA's CCI list.

    Args:
        path: ``U_CCI_List.xml`` or an equivalent document.
        revision: NIST SP 800-53 revision to resolve against.

    A CCI with no reference for *revision* maps to nothing rather than silently
    falling back to another revision. Rev 4 and Rev 5 moved requirements between
    controls, so a silent fallback would attribute findings to the wrong control
    and the error would be invisible in the report.
    """
    root = load_xml(path)
    mapping: dict[str, tuple[str, ...]] = {}

    for item in iter_local(root, "cci_item"):
        cci_id = (item.get("id") or "").strip()
        if not cci_id:
            continue
        controls: set[str] = set()
        for reference in iter_local(item, "reference"):
            if not _matches_revision(reference, revision):
                continue
            control = normalise_control_id(reference.get("index", ""))
            if control:
                controls.add(control)
        if controls:
            mapping[cci_id] = tuple(sorted(controls))

    return CciIndex(mapping=mapping)
