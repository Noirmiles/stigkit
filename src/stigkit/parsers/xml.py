"""Hardened XML loading and namespace-agnostic element helpers.

Why this module exists
----------------------
stigkit parses XML it did not author: benchmarks downloaded from DISA, results
emitted by a scanner, CCI lists passed in by an operator. Python's stock
``xml.etree.ElementTree`` resolves external entities and expands nested ones,
which makes a malicious or merely malformed input into two real bugs:

* **XXE** -- ``<!ENTITY xxe SYSTEM "file:///etc/passwd">`` makes the parser read
  local files (or reach out over the network) and splice the contents into the
  document, where they land in the report.
* **Entity expansion DoS** -- the "billion laughs" pattern exhausts memory
  before any of our code runs.

``defusedxml`` disables both. Every XML read in this project goes through
:func:`load_xml`; nothing imports ``xml.etree`` directly.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, parse

if TYPE_CHECKING:
    # Type-checking only: `Element` is the annotation for values that defusedxml
    # returns, and importing it has no effect at run time. Semgrep's
    # use-defused-xml rule matches any `xml.etree` import regardless of how it is
    # used, so the suppression is scoped to this single line with the reason
    # written down -- rather than excluding the rule in the Semgrep config, where
    # it would also stop catching a genuine `xml.etree.parse()` added later.
    # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
    from xml.etree.ElementTree import Element  # noqa: S405

__all__ = [
    "XmlParseError",
    "XmlSecurityError",
    "find_local",
    "findall_local",
    "iter_local",
    "load_xml",
    "local_name",
    "text_of",
]


class XmlParseError(Exception):
    """The document is not well-formed XML."""


class XmlSecurityError(Exception):
    """The document used an XML feature stigkit refuses to process.

    Raised for DTDs, internal entity definitions and external references. The
    message deliberately names only the file and the construct -- never any
    resolved content, so a rejected XXE payload cannot leak through the error.
    """


def load_xml(path: str | Path) -> Element:
    """Parse *path* with entity resolution and DTD processing disabled.

    Raises:
        XmlSecurityError: the document declared a DTD, entity or external ref.
        XmlParseError: the document is malformed or unreadable.
    """
    path = Path(path)
    try:
        tree = parse(
            path,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        raise XmlSecurityError(
            f"{path.name}: refused to parse - document uses a disallowed XML "
            f"construct ({type(exc).__name__}). This is how XXE and entity-expansion "
            f"attacks arrive; stigkit does not resolve them."
        ) from None
    except ParseError as exc:
        raise XmlParseError(f"{path.name}: malformed XML at {exc.position}") from exc
    except OSError as exc:
        raise XmlParseError(f"{path}: {exc.strerror}") from exc
    return tree.getroot()


def local_name(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from an ElementTree tag.

    XCCDF ships under at least three namespace URIs (1.1, 1.2, and vendor
    variants) and DISA content mixes them. Matching on local name means the
    parsers work across all of them without a namespace table to maintain.
    """
    return tag.rpartition("}")[2]


def iter_local(root: Element, name: str) -> Iterator[Element]:
    """Yield every descendant of *root* whose local name is *name*."""
    for elem in root.iter():
        if local_name(elem.tag) == name:
            yield elem


def findall_local(parent: Element, name: str) -> list[Element]:
    """Direct children of *parent* with local name *name*."""
    return [child for child in parent if local_name(child.tag) == name]


def find_local(parent: Element, name: str) -> Element | None:
    """First direct child of *parent* with local name *name*, or ``None``."""
    for child in parent:
        if local_name(child.tag) == name:
            return child
    return None


def text_of(elem: Element | None) -> str:
    """All text under *elem*, flattened and whitespace-normalised.

    XCCDF check and fix text legitimately contains nested markup, so ``.text``
    alone truncates at the first child element.
    """
    if elem is None:
        return ""
    return " ".join("".join(elem.itertext()).split())
