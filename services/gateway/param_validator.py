"""JSON Schema validation + sanitization on tools/call args (ARCHITECTURE.md §4.8).

Defense-in-depth, not a replacement for the upstream server's own validation.
"strict mode": unknown argument keys are rejected even when the schema doesn't say
`additionalProperties: false` — that's the part vanilla jsonschema doesn't give.
"""

import re
from typing import Any

import jsonschema

# Null bytes and control characters (tab/newline kept), plus path-traversal sequences.
_INJECTION = re.compile(r"\.\./|\.\.\\|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def validate(arguments: dict[str, Any], input_schema: dict[str, Any]) -> str | None:
    """Return an error string if arguments don't conform, else None."""
    properties = input_schema.get("properties")
    if isinstance(properties, dict):
        unknown = set(arguments) - set(properties)
        if unknown:
            return f"unknown argument field(s): {sorted(unknown)}"
    try:
        jsonschema.validate(arguments, input_schema)
    except jsonschema.ValidationError as exc:
        return f"schema validation failed: {exc.message}"
    except jsonschema.SchemaError as exc:
        # A broken upstream schema can't validate anything — fail closed.
        return f"tool schema itself is invalid: {exc.message}"
    return None


def sanitize(arguments: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Strip injection patterns from all string values, however nested.
    Returns the cleaned copy and the dotted paths of fields that were modified."""
    touched: list[str] = []

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, str):
            cleaned = _INJECTION.sub("", value)
            if cleaned != value:
                touched.append(path)
            return cleaned
        if isinstance(value, dict):
            return {k: walk(v, f"{path}.{k}" if path else str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(value)]
        return value

    cleaned = {k: walk(v, k) for k, v in arguments.items()}
    return cleaned, touched
