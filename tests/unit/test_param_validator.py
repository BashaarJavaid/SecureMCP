"""ARCHITECTURE.md §11 unit criterion: param validator edge cases
(nested objects, arrays, unicode)."""

from services.gateway.param_validator import sanitize, validate

ECHO_SCHEMA = {
    "type": "object",
    "properties": {"text": {"type": "string"}},
    "required": ["text"],
}

NESTED_SCHEMA = {
    "type": "object",
    "properties": {
        "config": {
            "type": "object",
            "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
        }
    },
}


def test_valid_arguments_pass() -> None:
    assert validate({"text": "hello"}, ECHO_SCHEMA) is None


def test_missing_required_field_fails() -> None:
    assert validate({}, ECHO_SCHEMA) is not None


def test_wrong_type_fails() -> None:
    assert validate({"text": 42}, ECHO_SCHEMA) is not None


def test_unknown_field_rejected_even_without_additional_properties_false() -> None:
    error = validate({"text": "hi", "bogus": 1}, ECHO_SCHEMA)
    assert error is not None
    assert "bogus" in error


def test_nested_objects_and_arrays_validate() -> None:
    assert validate({"config": {"paths": ["a", "b"]}}, NESTED_SCHEMA) is None
    assert validate({"config": {"paths": [1]}}, NESTED_SCHEMA) is not None


def test_unicode_passes_untouched() -> None:
    args = {"text": "héllo wörld — 日本語 🎌"}
    assert validate(args, ECHO_SCHEMA) is None
    cleaned, touched = sanitize(args)
    assert cleaned == args
    assert touched == []


def test_sanitize_strips_traversal_null_bytes_and_control_chars() -> None:
    cleaned, touched = sanitize({"text": "../../etc/passwd\x00\x1b[31m"})
    assert cleaned["text"] == "etc/passwd[31m"
    assert touched == ["text"]


def test_sanitize_preserves_newlines_and_tabs() -> None:
    cleaned, touched = sanitize({"text": "line1\nline2\tend"})
    assert cleaned["text"] == "line1\nline2\tend"
    assert touched == []


def test_sanitize_walks_nested_dicts_and_lists() -> None:
    cleaned, touched = sanitize(
        {"config": {"paths": ["ok", "..\\windows\\sam"], "note": "fine"}, "n": 3}
    )
    assert cleaned["config"]["paths"][1] == "windows\\sam"
    assert cleaned["n"] == 3
    assert touched == ["config.paths[1]"]


def test_clean_arguments_come_back_unchanged() -> None:
    args = {"a": "plain", "b": {"c": [1, 2, "three"]}}
    cleaned, touched = sanitize(args)
    assert cleaned == args
    assert touched == []
