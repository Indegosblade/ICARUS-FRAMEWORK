import pytest

from icarus.core.query import QueryResult


@pytest.mark.parametrize(
    "value",
    ["pipe|cell", "tick`span", "carriage\rreturn", "line\nbreak", "tab\tstop",
     "ansi\x1b[31mred", "nul\x00byte", r"literal\\slash", "c1\x85control",
     "long|" + "x" * 100],
)
def test_query_markdown_neutralizes_structural_and_control_characters(value):
    rendered = QueryResult([(value,)], [value], value).to_markdown()
    assert "\x1b" not in rendered
    assert "\x00" not in rendered
    assert "\x85" not in rendered
    assert "\r" not in rendered
    assert "\t" not in rendered
    assert "`" not in rendered
    if "|" in value:
        assert "\\|" in rendered
    assert "\\x" in rendered or "\\|" in rendered or "\\\\" in rendered


def test_query_markdown_preserves_readable_unicode():
    rendered = QueryResult([("café/東京",)], ["路径"], "résultats").to_markdown()
    assert "café/東京" in rendered
    assert "路径" in rendered
    assert "résultats" in rendered
