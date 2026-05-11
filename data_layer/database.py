import sqlite3
from datetime import datetime, timezone
from core.config import DB_PATH

DB_FILE = str(DB_PATH)


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        source TEXT,
        total_ips INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        event TEXT,
        risk_level TEXT,
        risk_score INTEGER,
        attack_type TEXT,
        recommended_action TEXT,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS raw_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        file_id INTEGER,
        log_type TEXT,
        ip TEXT,
        timestamp TEXT,
        method TEXT,
        url TEXT,
        status INTEGER,
        line_number INTEGER,
        parse_status TEXT,
        error_message TEXT,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
        FOREIGN KEY (file_id) REFERENCES analysis_files(id)
    )
    """)

    try:
        cur.execute("ALTER TABLE raw_logs ADD COLUMN file_id INTEGER")
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("ALTER TABLE raw_logs ADD COLUMN line_number INTEGER")
    except sqlite3.OperationalError:
        pass

    try:
        cur.execute("ALTER TABLE raw_logs ADD COLUMN parse_status TEXT")
    except sqlite3.OperationalError:
        pass



    cur.execute("""
    CREATE TABLE IF NOT EXISTS analysis_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
    )
    """)



    conn.commit()
    conn.close()

def create_analysis_file(run_id: int, file_name: str) -> int:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO analysis_files (
        run_id,
        file_name,
        created_at
    )
    VALUES (?, ?, ?)
    """, (
        run_id,
        file_name,
        datetime.now(timezone.utc).isoformat(),
    ))

    file_id = cur.lastrowid

    conn.commit()
    conn.close()

    return file_id

def save_analysis_run(results: list, source: str = "manual") -> int:
    conn = get_connection()
    cur = conn.cursor()

    total_ips = len(results)
    high_count = len([r for r in results if r.get("risk_level") == "HIGH"])
    medium_count = len([r for r in results if r.get("risk_level") == "MEDIUM"])
    low_count = len([r for r in results if r.get("risk_level") == "LOW"])

    cur.execute("""
    INSERT INTO analysis_runs (
        created_at, source, total_ips, high_count, medium_count, low_count
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        source,
        total_ips,
        high_count,
        medium_count,
        low_count,
    ))

    run_id = cur.lastrowid

    for item in results:
        cur.execute("""
        INSERT INTO detections (
            run_id,
            ip,
            event,
            risk_level,
            risk_score,
            attack_type,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            item.get("ip"),
            item.get("event"),
            item.get("risk_level"),
            item.get("risk_score"),
            item.get("attack_type"),
            item.get("recommended_action"),
        ))

    conn.commit()
    conn.close()

    return run_id


def get_analysis_runs(limit: int = 20):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, created_at, source, total_ips, high_count, medium_count, low_count
    FROM analysis_runs
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "created_at": r[1],
            "source": r[2],
            "total_ips": r[3],
            "high_count": r[4],
            "medium_count": r[5],
            "low_count": r[6],
        }
        for r in rows
    ]


def get_detections_by_run(run_id: int):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        id,
        run_id,
        ip,
        event,
        risk_level,
        risk_score,
        attack_type,
        recommended_action
    FROM detections
    WHERE run_id = ?
    ORDER BY risk_score DESC
    """, (run_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "run_id": r[1],
            "ip": r[2],
            "event": r[3],
            "risk_level": r[4],
            "risk_score": r[5],
            "attack_type": r[6],
            "recommended_action": r[7],
        }
        for r in rows
    ]

def save_raw_logs(run_id: int, raw_logs: list, file_id: int | None = None):
    conn = get_connection()
    cur = conn.cursor()

    for log in raw_logs:
        cur.execute("""
        INSERT INTO raw_logs (
            run_id,
            file_id,
            log_type,
            ip,
            timestamp,
            method,
            url,
            status,
            line_number,
            parse_status,
            error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            file_id,
            log.get("log_type"),
            log.get("ip"),
            log.get("timestamp"),
            log.get("method"),
            log.get("url"),
            log.get("status"),
            log.get("line_number"),
            log.get("parse_status"),
            log.get("error_message"),
        ))

    conn.commit()
    conn.close()



def update_analysis_run_summary(run_id: int, results: list):
    conn = get_connection()
    cur = conn.cursor()

    total_ips = len(results)
    high_count = len([r for r in results if r.get("risk_level") == "HIGH"])
    medium_count = len([r for r in results if r.get("risk_level") == "MEDIUM"])
    low_count = len([r for r in results if r.get("risk_level") == "LOW"])

    cur.execute("""
    UPDATE analysis_runs
    SET total_ips = ?, high_count = ?, medium_count = ?, low_count = ?
    WHERE id = ?
    """, (
        total_ips,
        high_count,
        medium_count,
        low_count,
        run_id
    ))

    conn.commit()
    conn.close()

def get_raw_logs_by_run(run_id: int):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT ip, timestamp, method, url, status, log_type, line_number, parse_status, error_message
    FROM raw_logs
    WHERE run_id = ?
      AND ip IS NOT NULL
      AND timestamp IS NOT NULL
    ORDER BY ip, timestamp, line_number
    """, (run_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "url": url,
            "status": status,
            "log_type": log_type,
            "line_number": line_number,
            "parse_status": parse_status,
            "error_message": error_message,
        }
        for ip, timestamp, method, url, status, log_type, line_number, parse_status, error_message in rows
    ]
