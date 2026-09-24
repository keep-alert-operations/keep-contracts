"""Schemas for the exact native field inventory; parsing preserves original object bytes."""

from appchi.ingestion.native import V1, V2, OPTIONAL, LIMITS


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
