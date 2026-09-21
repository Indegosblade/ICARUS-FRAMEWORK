import sys

import pytest

from icarus import __main__ as cli


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["icarus", "query", "db.sqlite"], "one of the arguments"),
        (["icarus", "query", "db.sqlite", "--sql", "SELECT 1", "--stats"], "not allowed"),
        (
            ["icarus", "query", "db.sqlite", "--table", "daemons", "--stats"],
            "--table requires --search",
        ),
    ],
)
def test_query_mode_is_exactly_one_and_table_only_applies_to_search(
    monkeypatch, capsys, argv, expected
):
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert expected in capsys.readouterr().err
