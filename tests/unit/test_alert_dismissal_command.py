import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from appchi.models import AlertCommand, BulkCommand, DismissalValue


def command(kind, value):
    return json.dumps(
        {"command_id": str(uuid4()), "expected_revision": "3", "kind": kind, "value": value}
    )


@pytest.mark.parametrize(
    "value",
    [
        {"duration_seconds": 60},
        {"duration_seconds": 30 * 86400, "reason": "known"},
        {"until": "2026-10-28T16:30:00Z"},
        {"until": "2026-10-28T16:30:00.123456+02:00"},
        None,
    ],
)
def test_set_dismissal_accepts_one_end_or_null(value):
    """Requirements: REV-49; alert operations 26, 29."""
    parsed = AlertCommand.model_validate_json(command("set_dismissal", value)).value
    assert parsed is None if value is None else isinstance(parsed, DismissalValue)


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"duration_seconds": 60, "until": "2026-10-28T16:30:00Z"},
        {"duration_seconds": 0},
        {"duration_seconds": 30 * 86400 + 1},
        {"duration_seconds": True},
        {"duration_seconds": "60"},
        {"until": "2026-10-28"},
        {"until": "2026-10-28T16:30:00"},
        {"duration_seconds": 60, "reason": "x" * 10001},
        {"duration_seconds": 60, "extra": 1},
        "2026-10-28T16:30:00Z",
    ],
)
def test_set_dismissal_rejects_other_values(value):
    """Requirements: REV-49; alert operations 26, 29."""
    with pytest.raises(ValidationError):
        AlertCommand.model_validate_json(command("set_dismissal", value))


def test_other_kinds_keep_string_values_and_bulk_excludes_dismissal():
    """Requirements: REV-49; alert operations 26, 27."""
    for kind in ("set_status", "set_assignee"):
        with pytest.raises(ValidationError):
            AlertCommand.model_validate_json(command(kind, {"duration_seconds": 60}))
    assert AlertCommand.model_validate_json(command("set_status", "resolved")).value == "resolved"
    alert = str(uuid4())
    with pytest.raises(ValidationError):
        BulkCommand.model_validate(
            {
                "command_id": str(uuid4()),
                "kind": "set_dismissal",
                "value": None,
                "items": [{"alert_id": alert, "expected_revision": "1"}],
            }
        )
