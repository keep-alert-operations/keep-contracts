from datetime import UTC, datetime
from uuid import UUID


def wire(value):
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("Authoritative timestamps require an explicit timezone")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, dict):
        return {
            key: (
                str(item)
                if isinstance(item, int)
                and not isinstance(item, bool)
                and key not in {"x", "y", "w", "h", "index", "limit", "page_size", "window_minutes"}
                else wire(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [wire(item) for item in value]
    return value
