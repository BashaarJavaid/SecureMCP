"""JSON Schema validation on tools/call args (ARCHITECTURE.md §4.8).

Defense-in-depth, not a replacement for the upstream server's own validation.
"strict mode": unknown argument keys are rejected even when the schema doesn't say
`additionalProperties: false` — that's the part vanilla jsonschema doesn't give.
Injection patterns in string values are rejected outright (item 31): rewriting
attacker input and forwarding it is the one place the §4.2 pipeline failed open.
"""

import re
from typing import Any

import jsonschema

# Null bytes and control characters (tab/newline kept), plus path-traversal sequences.
_INJECTION = re.compile(r"\.\./|\.\.\\|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _find_injection(value: Any, path: str) -> str | None:
    """Dotted path of the first string value matching _INJECTION, however nested."""
    if isinstance(value, str) and _INJECTION.search(value):
        return path
    if isinstance(value, dict):
        for k, v in value.items():
            if hit := _find_injection(v, f"{path}.{k}" if path else str(k)):
                return hit
    if isinstance(value, list):
        for i, v in enumerate(value):
            if hit := _find_injection(v, f"{path}[{i}]"):
                return hit
    return None


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
    for key, value in arguments.items():
        if hit := _find_injection(value, key):
            return f"path traversal or control character in argument {hit!r}"
    return None
