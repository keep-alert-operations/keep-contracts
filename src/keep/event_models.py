"""Versioned internal reference contracts; application content stays in PostgreSQL."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from keep.models import StrictModel


def bigint(value):
    if int(value) > 2**63 - 1:
        raise ValueError("Counter exceeds PostgreSQL bigint")
    return value


def instant(value):
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


Identifier = Annotated[
    str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
]
Counter = Annotated[
    str,
    Field(
        pattern=r"^(0|[1-9][0-9]{0,18})$",
        description="Canonical decimal int64, at most 9223372036854775807",
    ),
    AfterValidator(bigint),
]
Instant = Annotated[
    str,
    Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"),
    AfterValidator(instant),
]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SnapshotReference(StrictModel):
    tenant_id: Identifier
    seq: Counter


class PayloadReference(StrictModel):
    tenant_id: Identifier
    item_id: Identifier


class ChangedEnvelope(StrictModel):
    schema_version: Literal[1]
    event_id: Identifier
    kind: Literal["alerts.changed"]
    tenant_id: Identifier
    alert_id: Identifier
    projection_seq: Counter
    projection_version: Counter
    change_order: Counter
    original_admission_order: Counter | None
    native_version: Literal["v1", "v2"] | None
    actor_id: Identifier | None
    cause: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_-]*$")]
    effective_at: Instant
    recorded_at: Instant
    snapshot_ref: SnapshotReference
    snapshot_digest: Digest

    @model_validator(mode="after")
    def reference_scope(self):
        if (
            self.snapshot_ref.tenant_id != self.tenant_id
            or self.snapshot_ref.seq != self.projection_seq
        ):
            raise ValueError("Snapshot reference must match the envelope scope and sequence")
        if self.projection_seq == "0" or self.projection_version == "0":
            raise ValueError("Projection positions must be positive")
        return self


class ReceivedEnvelope(StrictModel):
    schema_version: Literal[1]
    event_id: Identifier
    kind: Literal["alerts.received"]
    tenant_id: Identifier
    admission_order: Counter
    native_version: Literal["v1", "v2"]
    actor_id: None
    cause: Literal["source"]
    received_at: Instant
    effective_at: Instant
    recorded_at: Instant
    payload_ref: PayloadReference
    payload_digest: Digest

    @model_validator(mode="after")
    def reference_scope(self):
        if (
            self.payload_ref.tenant_id != self.tenant_id
            or self.payload_ref.item_id != self.event_id
        ):
            raise ValueError("Payload reference must match the envelope tenant and item")
        if (
            self.admission_order == "0"
            or not self.received_at == self.effective_at == self.recorded_at
        ):
            raise ValueError("Admission order and receive boundary must be canonical")
        return self


EVENT_MODELS = {"alerts.changed": ChangedEnvelope, "alerts.received": ReceivedEnvelope}


class KafkaReceivedEnvelope(StrictModel):
    """Self-contained validated receipt; version 1 was a legacy PG reference."""

    schema_version: Literal[2]
    kind: Literal["alerts.received"]
    event_id: Identifier
    tenant_id: Identifier
    operator_id: Identifier | None
    credential_id: Identifier | None
    policy_generation: Counter | None
    native_version: Literal["v1", "v2"]
    received_at: Instant
    payload: dict[str, str]
    raw_json: Annotated[str, Field(max_length=65536)]
    time_defaulted: bool
    key_field: Annotated[str, Field(min_length=1, max_length=2048)]
    identity_material: str
    # keep-grafana-v1 maps Grafana to v2; keep-grafana-native-v1 maps it to v1 (REV-77).
    adapter_version: Literal["keep-grafana-v1", "keep-grafana-native-v1"] | None

    @model_validator(mode="after")
    def routing_scope(self):
        if self.native_version == "v2" and not all(
            (self.operator_id, self.credential_id, self.policy_generation)
        ):
            raise ValueError("V2 requires trusted credential routing")
        if self.native_version == "v1" and any(
            (self.operator_id, self.credential_id, self.policy_generation)
        ):
            raise ValueError("V1 cannot carry managed operator context")
        if self.adapter_version not in (
            None,
            "keep-grafana-v1" if self.native_version == "v2" else "keep-grafana-native-v1",
        ):
            raise ValueError("The Grafana adapter version does not match the native version")
        return self


EVENT_MODELS["alerts.received.v2"] = KafkaReceivedEnvelope
