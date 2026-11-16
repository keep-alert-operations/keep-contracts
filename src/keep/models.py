from datetime import datetime
from typing import Annotated, Literal
import re
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def uuid_string(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Canonical lowercase UUID required")
    return value


class Command(StrictModel):
    command_id: str
    expected_revision: str
    _command = field_validator("command_id")(uuid_string)

    @field_validator("expected_revision")
    @classmethod
    def revision(cls, value):
        if not re.fullmatch(r"0|[1-9][0-9]*", value) or int(value) > 2**63 - 1:
            raise ValueError("Decimal bigint revision required")
        return value


class DismissalValue(StrictModel):
    """A timed dismissal (REV-49): exactly one of an end instant or a duration."""

    until: str | None = None
    duration_seconds: Annotated[int, Field(ge=1, le=30 * 86400)] | None = None
    reason: Annotated[str, Field(max_length=10000)] | None = None

    @field_validator("until")
    @classmethod
    def instant(cls, value):
        if value is None:
            return value
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})", value
        ):
            raise ValueError("An RFC 3339 instant with an explicit offset is required")
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value

    @field_validator("reason")
    @classmethod
    def note(cls, value):
        if value is not None and "\x00" in value:
            raise ValueError("A plain-text reason is required")
        return value

    @model_validator(mode="after")
    def one_end(self):
        if (self.until is None) == (self.duration_seconds is None):
            raise ValueError("Give exactly one of until or duration_seconds")
        return self


class AlertCommand(Command):
    kind: Literal["set_status", "set_assignee", "set_dismissal"]
    value: str | DismissalValue | None

    @model_validator(mode="after")
    def typed_value(self):
        if self.kind == "set_dismissal":
            if isinstance(self.value, str):
                raise ValueError("A dismissal value is an object or null")
            return self
        if isinstance(self.value, DismissalValue):
            raise ValueError("Only set_dismissal takes an object value")
        if self.kind == "set_status" and self.value not in ("firing", "resolved"):
            raise ValueError("Status must be firing or resolved")
        if self.kind == "set_assignee" and self.value is not None:
            uuid_string(self.value)
        return self


class NoteCommand(Command):
    text: Annotated[str, Field(max_length=10000)]

    @field_validator("text")
    @classmethod
    def note(cls, value):
        if not value.strip() or "\x00" in value:
            raise ValueError("A nonblank plain-text note is required")
        return value.strip()


class BulkItem(StrictModel):
    alert_id: str
    expected_revision: str
    _id = field_validator("alert_id")(uuid_string)
    _revision = field_validator("expected_revision")(Command.revision.__func__)


class BulkCommand(StrictModel):
    command_id: str
    kind: Literal["set_status", "set_assignee"]
    value: str | None
    items: list[BulkItem]
    _id = field_validator("command_id")(uuid_string)

    @model_validator(mode="after")
    def selection(self):
        AlertCommand(
            command_id=self.command_id, expected_revision="0", kind=self.kind, value=self.value
        )
        unique = {}
        for item in self.items:
            if item.alert_id in unique and unique[item.alert_id] != item.expected_revision:
                raise ValueError("Repeated IDs have conflicting revisions")
            unique[item.alert_id] = item.expected_revision
        if not 1 <= len(unique) <= 100:
            raise ValueError("Select 1–100 distinct alerts")
        return self


class RumEvent(StrictModel):
    """One real-user-monitoring event from the browser (observability 9).

    The shape is checked here; which fields each kind needs, and that every value
    used as a metric label belongs to its closed set, is checked by the Product API.
    Events carry route templates and resource IDs, never addresses, query text or
    content.
    """

    kind: Literal[
        "web_vital",
        "page_view",
        "api",
        "api_error",
        "live",
        "live_disconnect",
        "js_error",
        "tab",
        "dropped",
    ]
    name: Annotated[str, Field(max_length=32)] | None = None
    view: Annotated[str, Field(max_length=32)] | None = None
    route: Annotated[str, Field(max_length=200)] | None = None
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] | None = None
    outcome: Annotated[str, Field(max_length=32)] | None = None
    state: Annotated[str, Field(max_length=32)] | None = None
    reason: Annotated[str, Field(max_length=32)] | None = None
    value: Annotated[int | float, Field(ge=0, le=86400)] | None = None
    count: Annotated[int, Field(ge=1, le=100000)] | None = None
    buckets: Annotated[list[Annotated[int, Field(ge=0, le=100000)]], Field(max_length=8)] | None = None
    status: Annotated[int, Field(ge=0, le=599)] | None = None
    request_id: str | None = None
    error_name: Annotated[str, Field(max_length=64)] | None = None
    stack: Annotated[str, Field(max_length=4000)] | None = None
    alert_id: str | None = None
    incident_id: str | None = None

    @field_validator("request_id", "alert_id", "incident_id")
    @classmethod
    def identifier(cls, value):
        return value if value is None else uuid_string(value)


class RumBatch(StrictModel):
    events: Annotated[list[RumEvent], Field(min_length=1, max_length=100)]
