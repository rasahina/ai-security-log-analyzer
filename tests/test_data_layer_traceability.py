from data_layer import database
from data_layer.log_parser import parse_log_lines


def test_parse_log_lines_assigns_original_line_numbers():
    records, _ = parse_log_lines([
        "# ignored comment",
        "2026-05-01T10:00:00+00:00 10.0.0.1 GET /login 401",
        "",
        "2026-05-01T10:00:05+00:00 10.0.0.1 GET /login 403",
    ])
    parsed = [record for record in records if record["parse_status"] == "parsed"]

    assert [record["line_number"] for record in parsed] == [2, 4]


def test_parse_log_lines_adds_stable_parse_status():
    records, _ = parse_log_lines([
        "# ignored comment",
        "2026-05-01T10:00:00+00:00 10.0.0.1 GET /login 401",
        "malformed",
    ])

    assert [
        (record["line_number"], record["parse_status"])
        for record in records
    ] == [
        (1, "ignored"),
        (2, "parsed"),
        (3, "failed"),
    ]
    assert all("parser_warnings" in record for record in records)


def test_parse_log_lines_adds_stable_parser_warnings():
    records, _ = parse_log_lines([
        "2026-05-01T10:00:00 10.0.0.1 GET /login 401",
        "not-a-timestamp 10.0.0.1 GET /login 401",
        "2026-05-01T10:00:00+00:00 10.0.0.1 GET /login BAD",
    ])

    assert [
        record["parser_warnings"]
        for record in records
    ] == [
        ["timezone_missing"],
        ["malformed_timestamp"],
        ["malformed_status"],
    ]


def test_raw_log_persistence_preserves_line_number(tmp_path, monkeypatch):
    db_path = tmp_path / "security_analyzer.db"
    monkeypatch.setattr(database, "DB_FILE", str(db_path))

    database.init_db()
    run_id = database.save_analysis_run([], source="test")
    database.save_raw_logs(
        run_id,
        [
            {
                "timestamp": "2026-05-01T10:00:00+00:00",
                "ip": "10.0.0.1",
                "method": "GET",
                "url": "/login",
                "status": 401,
                "log_type": "access",
                "line_number": 12,
                "parse_status": "parsed",
                "parser_warnings": ["timezone_missing"],
                "error_message": None,
            }
        ],
    )

    rows = database.get_raw_logs_by_run(run_id)

    assert rows[0]["line_number"] == 12
    assert rows[0]["parse_status"] == "parsed"
    assert rows[0]["parser_warnings"] == ["timezone_missing"]
