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


class AlertCommand(Command):
    kind: Literal["set_status", "set_acknowledged", "set_assignee"]
    value: str | bool | None

    @model_validator(mode="after")
    def typed_value(self):
        if self.kind == "set_status" and self.value not in ("firing", "resolved"):
            raise ValueError("Status must be firing or resolved")
        if self.kind == "set_acknowledged" and type(self.value) is not bool:
            raise ValueError("Acknowledgement must be boolean")
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
    kind: Literal["set_status", "set_acknowledged", "set_assignee"]
    value: str | bool | None
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
