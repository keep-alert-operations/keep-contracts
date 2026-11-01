from dataclasses import dataclass
from datetime import datetime, timezone
import re

from appchi.ingestion.native import (
    LIMITS,
    canonical,
    format_native_time,
    http_url,
    object_slices,
    parse_json,
    validate_native,
)
from appchi.shared.errors import AppError

ADAPTER_VERSION = "appchi-grafana-v1"


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
        return tuple("Appchi - " + name for name in names)


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


def map_webhook(raw: bytes, routing: OperatorRouting) -> list[MappedMember]:
    """Map only; caller must authenticate and atomically admit the valid subset.

    Retain original_bytes and adapter_version as source provenance. Invalid
    members produce indexed diagnostics without inventing admissible payloads.
    """
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
    expected_labels = routing.labels()
    originals = object_slices(raw)
    mapped = []
    for index, alert in enumerate(envelope["alerts"]):
        original = originals.get(("alerts", index), b"")
        try:
            if not isinstance(alert, dict):
                raise AppError("invalid_member", "Each Grafana alert must be an object")
            if len(original) > 65536:
                raise AppError(
                    "item_too_large", "Original Grafana members are limited to 64 KiB", 413
                )
            labels, annotations = alert.get("labels"), alert.get("annotations")
            if not isinstance(labels, dict) or not isinstance(annotations, dict):
                raise AppError("invalid_member", "Grafana labels and annotations must be objects")
            if any(
                not isinstance(value, str) for value in (*labels.values(), *annotations.values())
            ):
                raise AppError(
                    "invalid_member", "Grafana labels and annotations must contain strings"
                )
            if not any(labels.get(label) == "true" for label in expected_labels):
                raise AppError(
                    "operator_label_mismatch",
                    "Required authenticated-operator routing label is missing",
                )
            if not isinstance(alert.get("status"), str) or alert["status"] not in {
                "firing",
                "resolved",
            }:
                raise AppError(
                    "invalid_status", "Grafana per-alert status must be firing or resolved"
                )
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
            mapped.append(
                MappedMember(
                    index,
                    None,
                    b"",
                    {
                        "code": error.code,
                        "message": error.message,
                        "fields": error.fields,
                    },
                )
            )
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
