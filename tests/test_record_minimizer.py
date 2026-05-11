from data_layer.record_minimizer import load_policy, minimize_record


def test_policy_loads_allowed_fields_from_yaml():
    policy = load_policy()

    assert "timestamp" in policy["allowed_fields"]
    assert "parser_warnings" in policy["allowed_fields"]


def test_minimize_record_removes_unknown_fields():
    record = minimize_record({
        "timestamp": "2026-05-01T10:00:00+00:00",
        "ip": "10.0.0.1",
        "raw_line": "attacker controlled raw text",
        "unexpected": "drop me",
    })

    assert record == {
        "timestamp": "2026-05-01T10:00:00+00:00",
        "ip": "10.0.0.1",
    }


def test_minimize_record_preserves_runtime_metadata():
    record = minimize_record({
        "timestamp": "2026-05-01T10:00:00+00:00",
        "ip": "10.0.0.1",
        "method": "GET",
        "url": "/login",
        "status": 401,
        "log_type": "access",
        "level": None,
        "error_message": None,
        "user_agent": None,
        "line_number": 12,
        "parse_status": "parsed",
        "parser_warnings": ["timezone_missing"],
    })

    assert record["line_number"] == 12
    assert record["parse_status"] == "parsed"
    assert record["parser_warnings"] == ["timezone_missing"]


def test_minimize_record_normalizes_string_metadata():
    record = minimize_record({
        "ip": " 10.0.0.1 ",
        "parse_status": " parsed ",
        "parser_warnings": [" timezone_missing ", 123, None],
    })

    assert record == {
        "ip": "10.0.0.1",
        "parse_status": "parsed",
        "parser_warnings": ["timezone_missing"],
    }


def test_minimize_record_applies_configured_field_limits():
    record = minimize_record({
        "method": "GET-THIS-METHOD-NAME-IS-TOO-LONG",
        "url": "/" + ("a" * 3000),
        "error_message": "x" * 600,
    })

    assert record["method"] == "GET-THIS-METHOD-"
    assert len(record["url"]) == 2048
    assert len(record["error_message"]) == 512
