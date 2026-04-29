import sqlite3
import json
from datetime import datetime


DB_FILE = "data/security_analyzer.db"


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
        access_count INTEGER,
        failed_count INTEGER,
        suspicious_paths TEXT,
        status_counts TEXT,
        reasons TEXT,
        response_guides TEXT,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
    )
    """)

    conn.commit()
    conn.close()


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
        datetime.utcnow().isoformat(),
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
            recommended_action,
            access_count,
            failed_count,
            suspicious_paths,
            status_counts,
            reasons,
            response_guides
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            item.get("ip"),
            item.get("event"),
            item.get("risk_level"),
            item.get("risk_score"),
            item.get("attack_type"),
            item.get("recommended_action"),
            item.get("access_count"),
            item.get("failed_count"),
            json.dumps(item.get("suspicious_paths", []), ensure_ascii=False),
            json.dumps(item.get("status_counts", {}), ensure_ascii=False),
            json.dumps(item.get("reasons", []), ensure_ascii=False),
            json.dumps(item.get("response_guides", []), ensure_ascii=False),
        ))

    conn.commit()
    conn.close()

    return run_id