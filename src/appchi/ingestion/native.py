import hashlib
import json
import math
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from appchi.shared.errors import AppError

RETRY_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
V1 = {"application", "object", "node_name", "message", "operator", "time_created", "severity"}
V2 = {"application", "component", "message", "severity", "status", "site", "impact", "runbook_url"}
OPTIONAL = {"v1": {"key_field"}, "v2": {"node_name", "time_created", "name"}}
IDENTIFIERS = {
    "application",
    "object",
    "component",
    "node_name",
    "site",
    "operator",
    "key_field",
    "name",
}
LIMITS = {"message": 8192, "impact": 4096, "runbook_url": 2048, "key_field": 1024}


def canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(value) -> bytes:
    return hashlib.sha256(canonical(value)).digest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AppError("duplicate_key", "Duplicate JSON keys are not accepted.", 400)
        result[key] = value
    return result


def parse_json(raw: bytes):
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        _unicode(value)
        return value
    except (UnicodeError, ValueError, RecursionError):
        raise AppError("invalid_json", "Malformed UTF-8 JSON.", 400) from None


def _unicode(value):
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("unpaired surrogate")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite number")
    elif isinstance(value, dict):
        for key, item in value.items():
            _unicode(key)
            _unicode(item)
    elif isinstance(value, list):
        for item in value:
            _unicode(item)


def object_slices(raw: bytes):
    """Exact object bytes keyed by structural path; parser already validated the JSON."""
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    found = {}

    def walk(pos, path):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        start = pos
        if text[pos] == "{":
            pos += 1
            while True:
                while text[pos].isspace():
                    pos += 1
                if text[pos] == "}":
                    pos += 1
                    found[path] = text[start:pos].encode("utf-8")
                    return pos
                key, pos = decoder.raw_decode(text, pos)
                while text[pos].isspace():
                    pos += 1
                pos = walk(pos + 1, path + (key,))
                while text[pos].isspace():
                    pos += 1
                if text[pos] == ",":
                    pos += 1
        elif text[pos] == "[":
            pos += 1
            index = 0
            while True:
                while text[pos].isspace():
                    pos += 1
                if text[pos] == "]":
                    return pos + 1
                pos = walk(pos, path + (index,))
                index += 1
                while text[pos].isspace():
                    pos += 1
                if text[pos] == ",":
                    pos += 1
        else:
            _, pos = decoder.raw_decode(text, pos)
            return pos

    try:
        walk(0, ())
    except RecursionError:
        raise AppError("invalid_json", "JSON nesting is excessive.", 400) from None
    return found


def native_time(value: str):
    if not re.fullmatch(r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}", value):
        raise ValueError("timestamp")
    return datetime.strptime(value, "%d-%m-%Y %H:%M:%S").replace(tzinfo=UTC)


def format_native_time(value: datetime):
    return f"{value.day:02}-{value.month:02}-{value.year:04} {value.hour:02}:{value.minute:02}:{value.second:02}"


def validate_native(payload, version, raw):
    required = V1 if version == "v1" else V2
    if (
        not isinstance(payload, dict)
        or set(payload) - required - OPTIONAL[version]
        or required - set(payload)
    ):
        raise AppError(
            "invalid_fields", "Required fields are missing or unknown fields were supplied."
        )
    if len(raw) > 65536:
        raise AppError("item_too_large", "Native objects are limited to 64 KiB.", 413)
    for field, value in payload.items():
        if not isinstance(value, str) or not value.strip():
            raise AppError(
                "invalid_string", "Fields must be nonblank strings.", fields=[{"path": field}]
            )
        if len(value) > LIMITS.get(field, 256):
            raise AppError(
                "field_too_long",
                "Field exceeds its decoded character limit.",
                fields=[{"path": field}],
            )
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value) or "\x00" in value:
            raise AppError("invalid_character", "Invalid Unicode or NUL.", fields=[{"path": field}])
        if field in IDENTIFIERS and any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
            raise AppError(
                "invalid_character",
                "Identifiers cannot contain control characters.",
                fields=[{"path": field}],
            )
    severities = (
        {"error", "major", "warning", "clear"}
        if version == "v1"
        else {"critical", "high", "warning"}
    )
    if payload["severity"] not in severities or (
        version == "v2" and payload["status"] not in {"firing", "resolved", "suspended"}
    ):
        raise AppError("invalid_enum", "Invalid severity or status.")
    if "time_created" in payload:
        try:
            native_time(payload["time_created"])
        except ValueError:
            raise AppError("invalid_time", "Expected valid UTC DD-MM-YYYY HH:mm:ss.") from None
    if "runbook_url" in payload and not http_url(payload["runbook_url"]):
        raise AppError(
            "invalid_url", "Expected an absolute HTTP(S) URL without credentials or whitespace."
        )
    return dict(payload)


def http_url(url: str) -> bool:
    """An absolute HTTP(S) URL with a host, without credentials, whitespace or controls."""
    try:
        parts = urlsplit(url)
        valid = (
            parts.scheme in {"http", "https"}
            and parts.hostname
            and not parts.username
            and not parts.password
            and "@" not in parts.netloc
        )
        return bool(valid) and not any(
            c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 for c in url
        )
    except ValueError:
        return False


def identity(payload, version, operator_id=None):
    if version == "v1":
        key = payload.get("key_field")
        if key is None:
            key = "v1:" + "".join(
                f"{len(payload[f].encode())}:{payload[f]}"
                for f in ("application", "object", "node_name")
            )
        material = canonical(
            [payload[f] for f in ("application", "object", "node_name", "operator")]
        )
    else:
        fields = [
            2,
            str(operator_id),
            payload["application"],
            payload["component"],
            payload.get("node_name"),
            payload["severity"],
            payload["site"],
            payload["impact"],
            payload["runbook_url"],
        ]
        # A supplied name is the tenth input under identity format 2 (REV-54);
        # unnamed deliveries keep format 1, so their existing keys are unchanged.
        named = "name" in payload
        if named:
            fields.append(payload["name"])
        encoded = (
            "["
            + ",".join(
                "null" if v is None else str(v) if isinstance(v, int) else _identity_string(v)
                for v in fields
            )
            + "]"
        )
        material = f"alerts:v2:identity:{2 if named else 1}\n".encode() + encoded.encode()
        key = hashlib.sha256(material).hexdigest()
    return key, hashlib.sha256(key.encode()).digest(), material


def _identity_string(value):
    return (
        '"'
        + "".join(
            '\\"' if c == '"' else "\\\\" if c == "\\" else f"\\u{ord(c):04x}" if ord(c) < 32 else c
            for c in value
        )
        + '"'
    )
