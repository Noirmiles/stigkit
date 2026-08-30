"""The tool parses XML it did not author. These tests pin the hardening.

If someone swaps defusedxml back to xml.etree for convenience, these fail.
"""

from __future__ import annotations

import pytest

from stigkit.parsers.xccdf import parse_benchmark
from stigkit.parsers.xml import XmlSecurityError


def test_xxe_external_entity_is_refused(fixtures):
    """A benchmark declaring an external entity must be rejected, not resolved."""
    with pytest.raises(XmlSecurityError):
        parse_benchmark(fixtures / "malicious_xxe.xml")


def test_xxe_payload_never_reaches_output(fixtures):
    """Belt and braces: even the error path must not carry file contents."""
    try:
        parse_benchmark(fixtures / "malicious_xxe.xml")
    except XmlSecurityError as exc:
        assert "root:" not in str(exc)
        assert "/bin/bash" not in str(exc)
