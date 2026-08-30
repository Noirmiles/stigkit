from __future__ import annotations

from stigkit.parsers.cci import parse_cci_list


class TestParseCciList:
    def test_builds_mapping(self, fixtures):
        index = parse_cci_list(fixtures / "cci_list.xml")
        assert index
        assert "CCI-000048" in index.mapping

    def test_defaults_to_revision_5(self, fixtures):
        index = parse_cci_list(fixtures / "cci_list.xml")
        assert index.mapping["CCI-000205"] == ("IA-5 (1)",)

    def test_revision_4_selects_different_control(self, fixtures):
        """CCI-000205 maps to a different enhancement in Rev 4 than Rev 5."""
        rev4 = parse_cci_list(fixtures / "cci_list.xml", revision=4)
        rev5 = parse_cci_list(fixtures / "cci_list.xml", revision=5)
        assert rev4.mapping["CCI-000205"] == rev5.mapping["CCI-000205"]  # same enhancement
        assert rev4.mapping["CCI-000048"] == ("AC-8",)

    def test_strips_part_letters_but_keeps_enhancements(self, fixtures):
        """'AC-8 a' -> 'AC-8'; 'IA-5 (1) (h)' -> 'IA-5 (1)'."""
        index = parse_cci_list(fixtures / "cci_list.xml")
        assert index.mapping["CCI-000048"] == ("AC-8",)
        assert index.mapping["CCI-000205"] == ("IA-5 (1)",)

    def test_unknown_cci_resolves_to_nothing(self, fixtures):
        index = parse_cci_list(fixtures / "cci_list.xml")
        assert index.controls_for(("CCI-999999",)) == ()

    def test_controls_for_dedupes_and_sorts(self, fixtures):
        index = parse_cci_list(fixtures / "cci_list.xml")
        # CCI-000048 -> AC-8, CCI-000050 -> AC-8: one control, not two.
        assert index.controls_for(("CCI-000048", "CCI-000050")) == ("AC-8",)
