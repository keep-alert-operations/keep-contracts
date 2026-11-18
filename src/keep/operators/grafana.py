from dataclasses import dataclass
from datetime import datetime, timezone
import re

from keep.ingestion.native import (
    LIMITS,
    canonical,
    format_native_time,
    http_url,
    object_slices,
    parse_json,
    validate_native,
)
from keep.shared.errors import AppError

ADAPTER_VERSION = "keep-grafana-v1"
# REV-77: Grafana's standard webhook mapped to native v1 for Global.
NATIVE_V1_ADAPTER_VERSION = "keep-grafana-native-v1"
V1_LABELS = ("application", "object", "node_name", "operator", "severity")
# Where each mapped v1 field comes from, so errors name the Grafana source.
V1_SOURCES = {
    **{name: "labels." + name for name in (*V1_LABELS, "key_field")},
    "message": "annotations.message",
    "time_created": "startsAt",
}


@dataclass(frozen=True)
class OperatorRouting:
    name: str
    pending_name: str | None = None
    rename_pending: bool = False
    both_claims_held: bool = False

    def labels(self) -> tuple[str, ...]:
        names = [self.name]
        if self.pending_name is not None:
            if not self.rename_pending or not self.both_claims_held:
                raise AppError(
                    "rename_proof_missing",
                    "Pending routing name lacks authoritative rename proof",
                    503,
                )
            names.append(self.pending_name)
        return tuple("Keep - " + name for name in names)


@dataclass(frozen=True)
class MappedMember:
    index: int
    payload: dict | None
    original_bytes: bytes
    error: dict | None = None
    adapter_version: str = ADAPTER_VERSION
    event_id: None = None  # Fingerprints and startsAt are deliberately not retry IDs.


def _starts_at(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        value,
    ):
        raise AppError(
            "invalid_time", "Grafana startsAt must be an RFC3339 timestamp with an offset"
        )
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise AppError("invalid_time", "Grafana startsAt has an invalid offset")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        return format_native_time(instant.replace(microsecond=0))
    except (ValueError, OverflowError):
        raise AppError(
            "invalid_time", "Grafana startsAt is outside the supported calendar"
        ) from None


def _envelope(raw: bytes) -> tuple[list, dict]:
    """Validate the standard webhook envelope; return its alerts and their bytes."""
    if len(raw) > 4 * 1024 * 1024:
        raise AppError("body_too_large", "Grafana bodies are limited to 4 MiB", 413)
    envelope = parse_json(raw)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("alerts"), list):
        raise AppError("invalid_envelope", "Grafana payload requires an alerts array", 400)
    if "version" in envelope and envelope["version"] != "1":
        raise AppError("unsupported_grafana_envelope", "Unsupported Grafana webhook version")
    if not 1 <= len(envelope["alerts"]) <= 100:
        raise AppError("batch_size", "Grafana bodies require 1–100 alerts", 413)
    truncated = envelope.get("truncatedAlerts", 0)
    if type(truncated) is not int or truncated != 0:
        raise AppError(
            "grafana_truncated", "A truncated or invalid Grafana notification cannot be admitted"
        )
    return envelope["alerts"], object_slices(raw)


def _member_maps(alert, original: bytes) -> tuple[dict, dict]:
    """Check one member's shape; return its labels and annotations."""
    if not isinstance(alert, dict):
        raise AppError("invalid_member", "Each Grafana alert must be an object")
    if len(original) > 65536:
        raise AppError("item_too_large", "Original Grafana members are limited to 64 KiB", 413)
    labels, annotations = alert.get("labels"), alert.get("annotations")
    if not isinstance(labels, dict) or not isinstance(annotations, dict):
        raise AppError("invalid_member", "Grafana labels and annotations must be objects")
    if any(not isinstance(value, str) for value in (*labels.values(), *annotations.values())):
        raise AppError("invalid_member", "Grafana labels and annotations must contain strings")
    return labels, annotations


def _status(alert: dict) -> str:
    if not isinstance(alert.get("status"), str) or alert["status"] not in {
        "firing",
        "resolved",
    }:
        raise AppError("invalid_status", "Grafana per-alert status must be firing or resolved")
    return alert["status"]


def _failed(index: int, error: AppError) -> MappedMember:
    return MappedMember(
        index,
        None,
        b"",
        {"code": error.code, "message": error.message, "fields": error.fields},
    )


def map_webhook(raw: bytes, routing: OperatorRouting) -> list[MappedMember]:
    """Map only; caller must authenticate and atomically admit the valid subset.

    Retain original_bytes and adapter_version as source provenance. Invalid
    members produce indexed diagnostics without inventing admissible payloads.
    """
    alerts, originals = _envelope(raw)
    expected_labels = routing.labels()
    mapped = []
    for index, alert in enumerate(alerts):
        original = originals.get(("alerts", index), b"")
        try:
            labels, annotations = _member_maps(alert, original)
            if not any(labels.get(label) == "true" for label in expected_labels):
                raise AppError(
                    "operator_label_mismatch",
                    "Required authenticated-operator routing label is missing",
                )
            _status(alert)
            payload = {
                name: labels[name]
                for name in ("application", "component", "severity", "site")
                if name in labels
            }
            payload.update(
                {
                    name: annotations[name]
                    for name in ("message", "impact", "runbook_url")
                    if name in annotations
                }
            )
            if "node_name" in labels:
                payload["node_name"] = labels["node_name"]
            # Grafana sets alertname to the mandatory rule title (REV-54).
            if "alertname" not in labels:
                raise AppError(
                    "invalid_fields",
                    "Grafana alertname label (the alert rule name) is required",
                    fields=[{"path": "labels.alertname"}],
                )
            payload["name"] = labels["alertname"]
            payload["status"] = alert["status"]
            payload["time_created"] = _starts_at(alert.get("startsAt"))
            payload = validate_native(payload, "v2", canonical(payload))
            mapped.append(MappedMember(index, payload, original))
        except AppError as error:
            mapped.append(_failed(index, error))
    return mapped


def map_webhook_v1(raw: bytes) -> list[MappedMember]:
    """Map Grafana's standard webhook to native v1 members for Global (REV-77).

    v1 is unauthenticated, so there is no operator routing label. Labels supply
    application, object, node_name, operator, severity and an optional key_field;
    the message annotation supplies message and startsAt supplies time_created. A
    resolved member becomes v1 severity clear, so the alert resolves and keeps its
    last known severity. Errors name the Grafana label or annotation at fault.
    """
    alerts, originals = _envelope(raw)
    mapped = []
    for index, alert in enumerate(alerts):
        original = originals.get(("alerts", index), b"")
        try:
            labels, annotations = _member_maps(alert, original)
            status = _status(alert)
            missing = [name for name in V1_LABELS if name not in labels]
            if missing or "message" not in annotations:
                raise AppError(
                    "invalid_fields",
                    "Required Grafana labels or annotations are missing",
                    fields=[{"path": V1_SOURCES[name]} for name in missing]
                    + ([] if "message" in annotations else [{"path": "annotations.message"}]),
                )
            payload = {name: labels[name] for name in V1_LABELS}
            if "key_field" in labels:
                payload["key_field"] = labels["key_field"]
            payload["message"] = annotations["message"]
            if payload["severity"] not in {"error", "major", "warning", "clear"}:
                raise AppError(
                    "invalid_enum",
                    "Grafana severity must be error, major, warning or clear",
                    fields=[{"path": "labels.severity"}],
                )
            if status == "resolved":
                payload["severity"] = "clear"
            payload["time_created"] = _starts_at(alert.get("startsAt"))
            try:
                payload = validate_native(payload, "v1", canonical(payload))
            except AppError as error:
                raise AppError(
                    error.code,
                    error.message,
                    error.status,
                    fields=[
                        {**field, "path": V1_SOURCES.get(field.get("path"), field.get("path"))}
                        for field in error.fields or []
                    ]
                    or None,
                ) from None
            mapped.append(
                MappedMember(index, payload, original, adapter_version=NATIVE_V1_ADAPTER_VERSION)
            )
        except AppError as error:
            mapped.append(_failed(index, error))
    return mapped


def rule_url(original: bytes) -> str | None:
    """The alert rule URL of one retained Grafana member (REV-55), else None.

    Grafana's per-alert generatorURL links to the rule that fired the alert. It
    is a transport field outside the native mapping, so a missing or invalid
    value leaves the alert without a rule URL instead of rejecting it.
    """
    try:
        member = parse_json(original)
    except AppError:
        return None
    url = member.get("generatorURL") if isinstance(member, dict) else None
    if not isinstance(url, str) or len(url) > LIMITS["runbook_url"] or not http_url(url):
        return None
    return url


def bearer_credential(headers: list[tuple[str, str]]) -> str:
    """Gateway-side pre-auth boundary; never forward the returned secret upstream."""
    authorization = [value for name, value in headers if name.lower() == "authorization"]
    if len(authorization) != 1 or any(name.lower() == "x-api-key" for name, _ in headers):
        raise AppError(
            "invalid_credential", "Grafana requires one unambiguous Bearer credential", 401
        )
    match = re.fullmatch(r"Bearer (vena_[A-Za-z0-9_-]{43})", authorization[0], re.IGNORECASE)
    if not match:
        raise AppError("invalid_credential", "Invalid Grafana Bearer credential", 401)
    # Scheme is case-insensitive; credential prefix/value remain case-sensitive.
    value = authorization[0].split(" ", 1)[1]
    if not value.startswith("vena_"):
        raise AppError("invalid_credential", "Invalid Grafana Bearer credential", 401)
    return value
