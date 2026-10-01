"""Schemas for the exact native field inventory; parsing preserves original object bytes."""

from appchi.ingestion.native import V1, V2, OPTIONAL, LIMITS


def admission_responses():
    item = {
        "type": "object",
        "required": ["index", "status", "disposition"],
        "properties": {
            "index": {"type": "integer", "minimum": 0},
            "status": {"type": "integer", "enum": [202, 422, 503]},
            "disposition": {"type": "string", "enum": ["accepted", "rejected", "publish_failed"]},
            "received_at": {"type": "string", "format": "date-time"},
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {"type": "string"},
                    "message": {"type": "string"},
                    "retryable": {"type": "boolean"},
                    "fields": {},
                },
            },
        },
    }
    schema = {
        "type": "object",
        "required": ["request_id", "results"],
        "properties": {
            "request_id": {"type": "string", "format": "uuid"},
            "results": {"type": "array", "minItems": 1, "maxItems": 100, "items": item},
        },
    }
    failure = {
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message", "request_id"],
                "properties": {
                    "code": {"type": "string"},
                    "message": {"type": "string"},
                    "request_id": {"type": "string"},
                    "fields": {},
                },
            }
        },
    }
    return {
        status: {
            "description": description,
            "content": {
                "application/json": {
                    "schema": schema if status in (202, 207) else {"oneOf": [schema, failure]}
                }
            },
        }
        for status, description in {
            202: "All items acknowledged by Kafka; eventual PostgreSQL application is not guaranteed.",
            207: "Mixed acceptance, validation rejection or unconfirmed publication. Retry failed members only.",
            422: "All members failed validation, or legacy metadata was invalid.",
            503: "Admission dependency/deadline failure, or no member was acknowledged and at least one publication failed. Acknowledgement uncertainty may leave Kafka duplicates.",
        }.items()
    }


def native_schema(version):
    required = V1 if version == "v1" else V2
    properties = {
        field: {"type": "string", "minLength": 1, "maxLength": LIMITS.get(field, 256)}
        for field in sorted(required | OPTIONAL[version])
    }
    properties["severity"]["enum"] = (
        ["error", "major", "warning", "clear"]
        if version == "v1"
        else ["critical", "high", "warning"]
    )
    properties["time_created"] = {
        "type": "string",
        "pattern": r"^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}$",
    }
    if version == "v2":
        properties["status"]["enum"] = ["firing", "suspended", "resolved"]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(required),
        "properties": properties,
    }


def request_schema(version):
    native = native_schema(version)
    return {
        "oneOf": [
            native,
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["alerts"],
                "properties": {
                    "alerts": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 100,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["payload"],
                            "properties": {
                                "event_id": {
                                    "type": "string",
                                    "pattern": r"^[A-Za-z0-9._:-]{1,128}$",
                                },
                                "payload": native,
                            },
                        },
                    }
                },
            },
        ]
    }
