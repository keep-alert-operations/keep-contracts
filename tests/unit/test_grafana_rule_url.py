import json

import pytest

from keep.operators.grafana import OperatorRouting, map_webhook, rule_url

RULE = "https://grafana.example.org/alerting/grafana/cpu-rule/view?orgId=1"


def member(**extra):
    return {
        "status": "firing",
        "startsAt": "2026-09-22T15:00:01Z",
        "labels": {
            "Keep - Payments": "true",
            "alertname": "High CPU",
            "application": "pay",
            "component": "cpu",
            "severity": "critical",
            "site": "dc1",
        },
        "annotations": {
            "message": "Problem",
            "impact": "Requests affected",
            "runbook_url": "https://example.org/runbook",
        },
        **extra,
    }


def test_generator_url_is_the_rule_url_of_the_retained_member():
    """Requirements: operator operations 18; alert operations 3 (REV-55)."""
    raw = json.dumps({"version": "1", "alerts": [member(generatorURL=RULE)]}).encode()
    mapped = map_webhook(raw, OperatorRouting("Payments"))[0]
    assert mapped.error is None
    # The native-equivalent payload is unchanged; the URL stays outside the hash.
    assert "generatorURL" not in mapped.payload and "alert_rule_url" not in mapped.payload
    assert rule_url(mapped.original_bytes) == RULE


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        " ",
        5,
        ["https://grafana.example.org/rule"],
        "/alerting/grafana/cpu-rule/view",
        "ftp://grafana.example.org/rule",
        "javascript:alert(1)",
        "https://user:secret@grafana.example.org/rule",
        "https://grafana.example.org/rule with space",
        "https://grafana.example.org/rule\u0085",
        "https://grafana.example.org/" + "a" * 2048,
    ],
)
def test_missing_or_invalid_generator_url_leaves_no_rule_url(value):
    """Requirements: operator operations 18 (REV-55)."""
    extra = {} if value is None else {"generatorURL": value}
    raw = json.dumps({"version": "1", "alerts": [member(**extra)]}).encode()
    mapped = map_webhook(raw, OperatorRouting("Payments"))[0]
    # The alert is still admitted; only the rule URL is absent.
    assert mapped.error is None and mapped.payload is not None
    assert rule_url(mapped.original_bytes) is None


def test_rule_url_accepts_the_runbook_length_limit_and_ignores_malformed_bytes():
    """Requirements: operator operations 18 (REV-55)."""
    longest = "https://grafana.example.org/" + "a" * (2048 - len("https://grafana.example.org/"))
    assert rule_url(json.dumps(member(generatorURL=longest)).encode()) == longest
    assert rule_url(b"not json") is None
    assert rule_url(b'["https://grafana.example.org/rule"]') is None
