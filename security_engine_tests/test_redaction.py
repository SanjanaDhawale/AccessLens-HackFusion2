from security_engine.redaction import redact_headers, redact_text


def test_authorization_header_is_redacted():
    headers = {
        "Authorization": "Bearer secret-token-123",
        "Content-Type": "application/json",
    }

    result = redact_headers(headers)

    assert result["Authorization"] == "[REDACTED]"
    assert result["Content-Type"] == "application/json"


def test_password_is_redacted():
    text = '{"username":"test","password":"secret123"}'
    result = redact_text(text)

    assert "secret123" not in result
    assert "[REDACTED]" in result


def test_bearer_token_is_redacted():
    text = "Authorization: Bearer abc123xyz"
    result = redact_text(text)

    assert "abc123xyz" not in result
    assert "[REDACTED]" in result


def test_pin_and_vin_are_redacted():
    text = '{"pin":"1234","vin":"ABC123XYZ"}'
    result = redact_text(text)

    assert "1234" not in result
    assert "ABC123XYZ" not in result


def test_normal_text_is_preserved():
    text = "The API returned status code 200."
    assert redact_text(text) == text