from data_layer import database
from data_layer.log_parser import parse_log_lines


def test_parse_log_lines_assigns_original_line_numbers():
    parsed, _ = parse_log_lines([
        "# ignored comment",
        "2026-05-01T10:00:00+00:00 10.0.0.1 GET /login 401",
        "",
        "2026-05-01T10:00:05+00:00 10.0.0.1 GET /login 403",
    ])

    assert [record["line_number"] for record in parsed] == [2, 4]


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
                "error_message": None,
            }
        ],
    )

    rows = database.get_raw_logs_by_run(run_id)

    assert rows[0]["line_number"] == 12
