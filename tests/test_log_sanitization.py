"""Direct unit tests for the log sanitization guarantee (see
docs/security-logging-design.md §5) - app/core/log_sanitizer.py's pure
functions, and app/core/logging_config.py's formatter that applies them
to every log record. Deliberately does not go through the HTTP layer;
tests/test_security_logging.py covers that a given operation actually
logs, this file covers that whatever gets logged is safe.
"""

import logging

from app.core.log_sanitizer import REDACTED_VALUE, filter_known_secrets, sanitize_log_fields
from app.core.logging_config import JSONLogFormatter


def _make_record(msg: str = "test.event", **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="audit_log_service", level=logging.INFO, pathname=__file__, lineno=1, msg=msg, args=None, exc_info=None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


# --- sanitize_log_fields: key-name-based redaction --------------------------------


def test_password_field_is_redacted_regardless_of_value():
    result = sanitize_log_fields({"password": "hunter2"})

    assert result["password"] == REDACTED_VALUE


def test_password_hash_field_is_redacted():
    result = sanitize_log_fields({"password_hash": "$argon2id$v=19$..."})

    assert result["password_hash"] == REDACTED_VALUE


def test_access_token_field_is_redacted():
    result = sanitize_log_fields({"access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig"})

    assert result["access_token"] == REDACTED_VALUE


def test_secret_key_field_is_redacted():
    result = sanitize_log_fields({"secret_key": "some-signing-key-value"})

    assert result["secret_key"] == REDACTED_VALUE


def test_authorization_header_field_is_redacted():
    result = sanitize_log_fields({"Authorization": "Bearer sometoken"})

    assert result["Authorization"] == REDACTED_VALUE


def test_key_matching_is_case_insensitive():
    result = sanitize_log_fields({"PASSWORD": "hunter2", "UserToken": "abc"})

    assert result["PASSWORD"] == REDACTED_VALUE
    assert result["UserToken"] == REDACTED_VALUE


def test_sensitive_key_inside_a_nested_dict_is_redacted():
    result = sanitize_log_fields({"context": {"password": "hunter2", "username": "writer"}})

    assert result["context"]["password"] == REDACTED_VALUE
    assert result["context"]["username"] == "writer"


# --- sanitize_log_fields: value-shape-based redaction -----------------------------


def test_jwt_shaped_string_is_redacted_under_an_innocuous_key():
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dGhpc2lzYXNpZ25hdHVyZQ"

    result = sanitize_log_fields({"note": jwt_like})

    assert result["note"] == REDACTED_VALUE


def test_jwt_shaped_string_inside_a_list_is_redacted():
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.dGhpc2lzYXNpZ25hdHVyZQ"

    result = sanitize_log_fields({"items": [jwt_like, "plain-value"]})

    assert result["items"] == [REDACTED_VALUE, "plain-value"]


def test_ordinary_string_with_dots_is_not_treated_as_a_jwt():
    result = sanitize_log_fields({"note": "version 1.2.3"})

    assert result["note"] == "version 1.2.3"


def test_a_known_secret_value_is_redacted_wherever_it_appears():
    known = filter_known_secrets(["super-secret-signing-key-value"])

    result = sanitize_log_fields(
        {"exception_message": "connection failed: password=super-secret-signing-key-value"},
        known_secrets=known,
    )

    assert result["exception_message"] == REDACTED_VALUE


def test_short_known_secret_candidates_are_filtered_out():
    """Below the minimum length, a "secret" is too likely to coincide
    with ordinary text - filter_known_secrets excludes it rather than
    over-redacting."""
    known = filter_known_secrets(["short"])

    assert known == frozenset()


# --- sanitize_log_fields: ordinary fields pass through unchanged ------------------


def test_ordinary_business_fields_are_not_redacted():
    result = sanitize_log_fields(
        {"username": "writer", "actor_id": "user-1", "record_count": 3, "newly_redacted_fields": ["accountNumber"]}
    )

    assert result == {
        "username": "writer",
        "actor_id": "user-1",
        "record_count": 3,
        "newly_redacted_fields": ["accountNumber"],
    }


# --- JSONLogFormatter: end-to-end on a real LogRecord -----------------------------


def test_formatter_redacts_a_sensitive_extra_field():
    record = _make_record(event="test.event", password="hunter2", username="writer")

    formatted = JSONLogFormatter().format(record)

    assert "hunter2" not in formatted
    assert '"password":"[REDACTED]"' in formatted
    assert '"username":"writer"' in formatted


def test_formatter_output_is_valid_json_with_expected_envelope():
    import json

    record = _make_record(event="auth.login.success", correlation_id="abc-123", username="writer")

    parsed = json.loads(JSONLogFormatter().format(record))

    assert parsed["event"] == "auth.login.success"
    assert parsed["correlationId"] == "abc-123"
    assert parsed["username"] == "writer"
    assert parsed["level"] == "INFO"
    assert "timestamp" in parsed


def test_formatter_redacts_the_configured_signing_secret_if_it_ever_appears():
    formatter = JSONLogFormatter()
    real_secret = next(iter(formatter._known_secrets)) if formatter._known_secrets else None
    assert real_secret is not None, "test .env.test's SECRET_KEY should be long enough to be a known secret"

    record = _make_record(event="unhandled_exception", exception_message=f"failed using key {real_secret}")

    formatted = JSONLogFormatter().format(record)

    assert real_secret not in formatted
