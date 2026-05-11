from datetime import timezone

from data_layer import event_format_adapter


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
                "error_message": None,
            }
        ],
    )

    events_by_ip = event_format_adapter.get_ip_events(1)

    timestamp = events_by_ip["10.0.0.1"][0]["timestamp"]
    assert timestamp.tzinfo is timezone.utc
    assert timestamp.isoformat() == "2026-05-01T10:30:00+00:00"
    assert events_by_ip["10.0.0.1"][0]["line_number"] == 7


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
                "error_message": None,
            },
        ],
    )

    assert event_format_adapter.get_ip_events(1) == {}
