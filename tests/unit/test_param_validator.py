"""ARCHITECTURE.md §11 unit criterion: param validator edge cases
(nested objects, arrays, unicode)."""

from services.gateway.param_validator import validate

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
    assert validate({"text": "héllo wörld — 日本語 🎌"}, ECHO_SCHEMA) is None


def test_traversal_null_bytes_and_control_chars_are_rejected() -> None:
    for text in ("../../etc/passwd", "..\\windows\\sam", "a\x00b", "a\x1b[31m"):
        error = validate({"text": text}, ECHO_SCHEMA)
        assert error is not None
        assert "'text'" in error


def test_reformed_traversal_is_rejected_not_reformed() -> None:
    # Item 31: the old single-pass sanitizer turned these into '../…' and forwarded.
    for text in ("....//etc/passwd", "..././etc/passwd"):
        assert validate({"text": text}, ECHO_SCHEMA) is not None


def test_newlines_and_tabs_still_pass() -> None:
    assert validate({"text": "line1\nline2\tend"}, ECHO_SCHEMA) is None


def test_injection_is_found_however_nested() -> None:
    error = validate(
        {"config": {"paths": ["ok", "..\\windows\\sam"]}},
        NESTED_SCHEMA,
    )
    assert error is not None
    assert "'config.paths[1]'" in error
