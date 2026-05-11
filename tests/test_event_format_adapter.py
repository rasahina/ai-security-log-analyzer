from datetime import timezone

from data_layer import event_format_adapter


def _row(**overrides):
    row = {
        "ip": "10.0.0.1",
        "timestamp": "2026-05-01T10:30:00+00:00",
        "method": "GET",
        "url": "/login",
        "status": 401,
        "log_type": "access",
        "line_number": 1,
        "parse_status": "parsed",
        "parser_warnings": [],
        "error_message": None,
    }
    row.update(overrides)
    return row


def test_get_ip_events_normalizes_aware_timestamps_to_utc(monkeypatch):
    monkeypatch.setattr(
        event_format_adapter,
        "get_raw_logs_by_run",
        lambda run_id: [
            {
                "ip": "10.0.0.1",
                "timestamp": "2026-05-01T19:30:00+09:00",
                "method": "GET",
                "url": "/login",
                "status": 401,
                "log_type": "access",
                "line_number": 7,
                "parse_status": "parsed",
                "parser_warnings": ["timezone_missing"],
                "error_message": None,
            }
        ],
    )

    events_by_ip = event_format_adapter.get_ip_events(1)

    timestamp = events_by_ip["10.0.0.1"][0]["timestamp"]
    assert timestamp.tzinfo is timezone.utc
    assert timestamp.isoformat() == "2026-05-01T10:30:00+00:00"
    assert events_by_ip["10.0.0.1"][0]["line_number"] == 7
    assert events_by_ip["10.0.0.1"][0]["parser_warnings"] == ["timezone_missing"]


def test_runtime_eligibility_explains_parse_status_skip():
    assert event_format_adapter.get_runtime_eligibility(
        _row(parse_status="ignored")
    ) == {
        "is_runtime_eligible": False,
        "runtime_exclusion_reason": "parse_status_not_parsed",
    }


def test_runtime_eligibility_explains_missing_timestamp_skip():
    assert event_format_adapter.get_runtime_eligibility(
        _row(timestamp=None)
    ) == {
        "is_runtime_eligible": False,
        "runtime_exclusion_reason": "timestamp_missing",
    }


def test_runtime_eligibility_explains_malformed_timestamp_skip():
    assert event_format_adapter.get_runtime_eligibility(
        _row(timestamp="not-a-timestamp")
    ) == {
        "is_runtime_eligible": False,
        "runtime_exclusion_reason": "timestamp_malformed",
    }


def test_runtime_eligibility_explains_naive_timestamp_skip():
    assert event_format_adapter.get_runtime_eligibility(
        _row(timestamp="2026-05-01T10:30:00")
    ) == {
        "is_runtime_eligible": False,
        "runtime_exclusion_reason": "timezone_missing",
    }


def test_runtime_eligibility_explains_missing_ip_skip():
    assert event_format_adapter.get_runtime_eligibility(
        _row(ip=None)
    ) == {
        "is_runtime_eligible": False,
        "runtime_exclusion_reason": "source_ip_missing",
    }


def test_runtime_eligibility_accepts_valid_runtime_row():
    assert event_format_adapter.get_runtime_eligibility(_row()) == {
        "is_runtime_eligible": True,
        "runtime_exclusion_reason": None,
    }


def test_get_ip_events_skips_naive_timestamps(monkeypatch):
    monkeypatch.setattr(
        event_format_adapter,
        "get_raw_logs_by_run",
        lambda run_id: [
            {
                "ip": "10.0.0.1",
                "timestamp": "2026-05-01T10:30:00",
                "method": "GET",
                "url": "/login",
                "status": 401,
                "log_type": "access",
                "line_number": 4,
                "parse_status": "parsed",
                "parser_warnings": ["timezone_missing"],
                "error_message": None,
            }
        ],
    )

    assert event_format_adapter.get_ip_events(1) == {}


def test_get_ip_events_skips_ignored_and_failed_rows(monkeypatch):
    monkeypatch.setattr(
        event_format_adapter,
        "get_raw_logs_by_run",
        lambda run_id: [
            {
                "ip": "10.0.0.1",
                "timestamp": "2026-05-01T10:30:00+00:00",
                "method": "GET",
                "url": "/ignored",
                "status": 401,
                "log_type": "access",
                "line_number": 2,
                "parse_status": "ignored",
                "parser_warnings": [],
                "error_message": None,
            },
            {
                "ip": "10.0.0.1",
                "timestamp": "2026-05-01T10:30:01+00:00",
                "method": "GET",
                "url": "/failed",
                "status": 403,
                "log_type": "access",
                "line_number": 3,
                "parse_status": "failed",
                "parser_warnings": [],
                "error_message": None,
            },
        ],
    )

    assert event_format_adapter.get_ip_events(1) == {}


def test_get_ip_events_skips_missing_runtime_requirements(monkeypatch):
    monkeypatch.setattr(
        event_format_adapter,
        "get_raw_logs_by_run",
        lambda run_id: [
            _row(ip=None),
            _row(timestamp=None),
        ],
    )

    assert event_format_adapter.get_ip_events(1) == {}
