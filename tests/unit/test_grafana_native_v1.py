import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from keep.event_models import KafkaReceivedEnvelope
from keep.operators.grafana import (
    ADAPTER_VERSION,
    NATIVE_V1_ADAPTER_VERSION,
    OperatorRouting,
    map_webhook,
    map_webhook_v1,
)


def member(**update):
    alert = {
        "status": "firing",
        "startsAt": "2026-11-18T09:30:05.5+02:00",
        "generatorURL": "https://grafana.example.org/alerting/grafana/abc/view",
        "labels": {
            "alertname": "Disk full",
            "application": "billing",
            "object": "disk",
            "node_name": "db-03",
            "operator": "nagios-prod",
            "severity": "major",
        },
        "annotations": {"message": "Disk is 95% full"},
        "fingerprint": "not-an-id",
    }
    return {**alert, **update}


def body(*alerts):
    return json.dumps(
        {"version": "1", "status": "firing", "truncatedAlerts": 0, "alerts": list(alerts)}
    ).encode()


def test_firing_member_maps_to_native_v1():
    """Requirements: REV-77; operator operations 30; alert operations 1."""
    mapped = map_webhook_v1(body(member()))[0]
    assert mapped.error is None
    assert mapped.adapter_version == NATIVE_V1_ADAPTER_VERSION
    assert mapped.payload == {
        "application": "billing",
        "object": "disk",
        "node_name": "db-03",
        "operator": "nagios-prod",
        "severity": "major",
        "message": "Disk is 95% full",
        "time_created": "18-11-2026 07:30:05",
    }
    assert json.loads(mapped.original_bytes) == member()


def test_resolved_member_becomes_clear_and_key_field_is_kept():
    """Requirements: REV-77; operator operations 30; alert operations 4 and 6."""
    labels = dict(member()["labels"], key_field="billing-disk")
    mapped = map_webhook_v1(body(member(status="resolved", labels=labels)))[0]
    assert mapped.error is None
    assert mapped.payload["severity"] == "clear"
    assert mapped.payload["key_field"] == "billing-disk"


@pytest.mark.parametrize(
    ("update", "code", "paths"),
    [
        (
            {"labels": {"application": "billing", "node_name": "db-03", "severity": "major"}},
            "invalid_fields",
            ["labels.object", "labels.operator"],
        ),
        ({"annotations": {"summary": "no alias"}}, "invalid_fields", ["annotations.message"]),
        (
            {"labels": dict(member()["labels"], severity="critical")},
            "invalid_enum",
            ["labels.severity"],
        ),
        (
            {"labels": dict(member()["labels"], object=" ")},
            "invalid_string",
            ["labels.object"],
        ),
        ({"status": "suspended"}, "invalid_status", None),
    ],
)
def test_invalid_members_name_the_grafana_source(update, code, paths):
    """Requirements: REV-77; operator operations 30; alert operations 1 and 11."""
    mapped = map_webhook_v1(body(member(), member(**update)))
    assert mapped[0].error is None
    assert mapped[1].payload is None
    assert mapped[1].error["code"] == code
    assert (
        [field["path"] for field in mapped[1].error["fields"]]
        if mapped[1].error["fields"]
        else None
    ) == paths


def test_v2_adapter_still_requires_its_own_fields():
    """Requirements: REV-77; operator operations 18."""
    mapped = map_webhook(body(member()), OperatorRouting("Payments"))[0]
    assert mapped.payload is None
    assert mapped.error["code"] == "operator_label_mismatch"


def envelope(native_version, adapter_version, routed):
    ids = {
        "operator_id": str(uuid4()),
        "credential_id": str(uuid4()),
        "policy_generation": "1",
    }
    return {
        "schema_version": 2,
        "kind": "alerts.received",
        "event_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        **(ids if routed else dict.fromkeys(ids)),
        "native_version": native_version,
        "received_at": "2026-11-18T07:30:05.000000Z",
        "payload": {"message": "x"},
        "raw_json": "{}",
        "time_defaulted": False,
        "key_field": "k",
        "identity_material": "[]",
        "adapter_version": adapter_version,
    }


@pytest.mark.parametrize(
    ("native_version", "adapter_version", "routed"),
    [
        ("v1", None, False),
        ("v1", NATIVE_V1_ADAPTER_VERSION, False),
        ("v2", None, True),
        ("v2", ADAPTER_VERSION, True),
    ],
)
def test_received_envelope_accepts_matching_adapters(native_version, adapter_version, routed):
    """Requirements: REV-77; Kafka pipeline 2."""
    KafkaReceivedEnvelope.model_validate(envelope(native_version, adapter_version, routed))


@pytest.mark.parametrize(
    ("native_version", "adapter_version", "routed"),
    [
        ("v1", ADAPTER_VERSION, False),
        ("v2", NATIVE_V1_ADAPTER_VERSION, True),
        ("v1", NATIVE_V1_ADAPTER_VERSION, True),
    ],
)
def test_received_envelope_rejects_mismatched_adapters(native_version, adapter_version, routed):
    """Requirements: REV-77; Kafka pipeline 2."""
    with pytest.raises(ValidationError):
        KafkaReceivedEnvelope.model_validate(envelope(native_version, adapter_version, routed))
