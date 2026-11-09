from appchi.serialization import wire


def test_layout_and_table_rows_stay_numbers_other_integers_become_strings():
    """Requirements: REV-63; dashboard operations 14."""
    panel = {"x": 0, "y": 2, "w": 6, "h": 4, "rows": 25, "revision": 3}
    assert wire({"panels": [panel], "panel_count": 1}) == {
        "panels": [{"x": 0, "y": 2, "w": 6, "h": 4, "rows": 25, "revision": "3"}],
        "panel_count": "1",
    }
    # Report "rows" are lists of figures; their integers still serialize as strings.
    assert wire({"rows": [["rule", {"opened": 4}]]}) == {"rows": [["rule", {"opened": "4"}]]}
