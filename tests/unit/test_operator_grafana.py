import json

import pytest

from appchi.operators.grafana import OperatorRouting, bearer_credential, map_webhook
from appchi.shared.errors import AppError


def member():
    return {
        "status": "firing",
        "startsAt": "2026-09-22T15:00:01.123456789+03:00",
        "labels": {
            "Appchi - Payments": "true",
            "application": "pay",
            "component": "cpu",
            "severity": "critical",
            "site": "dc1",
            "tenant_id": "untrusted",
        },
        "annotations": {
            "message": "Problem",
            "impact": "Requests affected",
            "runbook_url": "https://example.org/runbook",
        },
        "fingerprint": "not-an-id",
    }


def body(*alerts, **extra):
    return json.dumps(
        {
            "version": "1",
            "status": "resolved",
            "truncatedAlerts": 0,
            "alerts": list(alerts),
            **extra,
        },
        ensure_ascii=False,
    ).encode()


def test_exact_native_mapping_ignores_group_status_and_untrusted_routing():
    raw = body(member())
    mapped = map_webhook(raw, OperatorRouting("Payments"))[0]
    assert mapped.error is None
    assert mapped.payload == {
        "application": "pay",
        "component": "cpu",
        "severity": "critical",
        "site": "dc1",
        "message": "Problem",
        "impact": "Requests affected",
        "runbook_url": "https://example.org/runbook",
        "status": "firing",
        "time_created": "22-09-2026 12:00:01",
    }
    assert json.loads(mapped.original_bytes) == member()
    assert mapped.event_id is None


@pytest.mark.parametrize(
    "update",
    [
        {"status": "suspended"},
        {"status": []},
        {"startsAt": "2026-09-22T12:00:00"},
        {"startsAt": "2026-09-22T12:00:60Z"},
        {"startsAt": "2026-09-22T12:00:00+24:00"},
        {"labels": {}},
        {"annotations": {"summary": "No message alias"}},
    ],
)
def test_invalid_members_preserve_indexed_partial_results(update):
    invalid = dict(member(), **update)
    mapped = map_webhook(body(member(), invalid, member()), OperatorRouting("Payments"))
    assert [entry.index for entry in mapped] == [0, 1, 2]
    assert mapped[0].payload and mapped[1].error and mapped[2].payload
    assert mapped[1].original_bytes == b""


def test_routing_label_exact_true_and_rename_requires_both_name_claims():
    alert = member()
    alert["labels"]["Appchi - Payments"] = "True"
    assert map_webhook(body(alert), OperatorRouting("Payments"))[0].error
    del alert["labels"]["Appchi - Payments"]
    alert["labels"]["Appchi - PAYMENTS"] = "true"
    assert map_webhook(body(alert), OperatorRouting("Payments"))[0].error
    routing = OperatorRouting("Payments", "PAYMENTS", True, True)
    assert map_webhook(body(alert), routing)[0].payload
    with pytest.raises(AppError):
        map_webhook(body(alert), OperatorRouting("Payments", "PAYMENTS", True, False))
    old = member()
    assert map_webhook(body(old), OperatorRouting("PAYMENTS"))[0].error


@pytest.mark.parametrize("truncated", [1, True, "0", -1, None])
def test_truncation_rejects_entire_request(truncated):
    with pytest.raises(AppError) as failure:
        map_webhook(body(member(), truncatedAlerts=truncated), OperatorRouting("Payments"))
    assert failure.value.code == "grafana_truncated"


def test_original_size_extra_fields_and_node_null_do_not_bypass_native_rules():
    alert = member()
    alert["extra"] = "x" * 66000
    assert (
        map_webhook(body(alert), OperatorRouting("Payments"))[0].error["code"] == "item_too_large"
    )
    alert = member()
    alert["labels"]["node_name"] = None
    assert map_webhook(body(alert), OperatorRouting("Payments"))[0].error
    alert = member()
    alert["labels"]["severity"] = "error"
    assert map_webhook(body(alert), OperatorRouting("Payments"))[0].error["code"] == "invalid_enum"


def test_duplicate_json_keys_and_ambiguous_headers_rejected():
    with pytest.raises(AppError):
        map_webhook(b'{"alerts":[],"alerts":[]}', OperatorRouting("Payments"))
    key = "vena_" + "a" * 43
    assert bearer_credential([("Authorization", "Bearer " + key)]) == key
    for headers in (
        [("Authorization", "Bearer " + key), ("X-API-Key", key)],
        [("Authorization", "Bearer " + key), ("authorization", "Bearer " + key)],
        [("Authorization", "Bearer " + key + ",Bearer other")],
    ):
        with pytest.raises(AppError):
            bearer_credential(headers)
