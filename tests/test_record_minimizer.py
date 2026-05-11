from data_layer.record_minimizer import minimize_record


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
