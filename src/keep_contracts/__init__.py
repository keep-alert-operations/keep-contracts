"""Access schemas bundled in the immutable contracts distribution."""
from pathlib import Path


def schema_path(name="openapi.json"):
    if Path(name).name != name or not name.endswith(".json"):
        raise ValueError("Expected a schema filename")
    return Path(__file__).parent / "schemas" / name
