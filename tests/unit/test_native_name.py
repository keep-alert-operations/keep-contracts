import hashlib

import pytest

from keep.ingestion.native import identity, validate_native
from keep.shared.errors import AppError

OPERATOR = "00000000-0000-4000-8000-000000000001"


def v2(**extra):
    return {
        "application": "pay",
        "component": "api",
        "message": "Problem",
        "severity": "critical",
        "status": "firing",
        "site": "dc1",
        "impact": "Checkout fails",
        "runbook_url": "https://example.org/runbook",
        **extra,
    }


def test_v2_name_is_optional_and_v1_rejects_it():
    """Requirements: alert operations field inventory, 1 (REV-54)."""
    assert validate_native(v2(name="Checkout errors"), "v2", b"{}")["name"] == "Checkout errors"
    assert "name" not in validate_native(v2(), "v2", b"{}")
    v1 = {
        "application": "a",
        "object": "b",
        "node_name": "c",
        "message": "m",
        "operator": "o",
        "time_created": "01-01-2026 00:00:00",
        "severity": "error",
    }
    with pytest.raises(AppError) as failure:
        validate_native({**v1, "name": "n"}, "v1", b"{}")
    assert failure.value.code == "invalid_fields"


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("", "invalid_string"),
        ("   ", "invalid_string"),
        (None, "invalid_string"),
        (7, "invalid_string"),
        ("x" * 257, "field_too_long"),
        ("tab\there", "invalid_character"),
        ("a\u0085b", "invalid_character"),
    ],
)
def test_v2_name_follows_identifier_rules(value, code):
    """Requirements: alert operations 1 (REV-54)."""
    with pytest.raises(AppError) as failure:
        validate_native(v2(name=value), "v2", b"{}")
    assert failure.value.code == code
    assert failure.value.fields == [{"path": "name"}]
    assert validate_native(v2(name=" é" + "x" * 254), "v2", b"{}")


def test_unnamed_identity_keeps_format_1_and_a_name_selects_format_2():
    """Requirements: alert operations 5, 7 (REV-54)."""
    key, digest, material = identity(v2(), "v2", OPERATOR)
    expected = (
        b"alerts:v2:identity:1\n"
        b'[2,"00000000-0000-4000-8000-000000000001","pay","api",null,"critical","dc1",'
        b'"Checkout fails","https://example.org/runbook"]'
    )
    assert material == expected
    assert key == hashlib.sha256(expected).hexdigest()
    assert digest == hashlib.sha256(key.encode()).digest()

    named_key, _, named = identity(v2(name='Disk "full"é'), "v2", OPERATOR)
    assert named == (
        b"alerts:v2:identity:2\n"
        b'[2,"00000000-0000-4000-8000-000000000001","pay","api",null,"critical","dc1",'
        b'"Checkout fails","https://example.org/runbook","Disk \\"full\\"\xc3\xa9"]'
    )
    assert named_key == hashlib.sha256(named).hexdigest() != key
    assert identity(v2(name='Disk "full"é', message="other"), "v2", OPERATOR)[0] == named_key
    assert identity(v2(name="Other"), "v2", OPERATOR)[0] not in {key, named_key}
    # The default name equals the unnamed key, yet sending it is a different identity.
    assert identity(v2(name=key), "v2", OPERATOR)[0] != key
