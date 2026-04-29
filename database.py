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
        recommended_action,
        access_count,
        failed_count,
        suspicious_paths,
        status_counts,
        reasons,
        response_guides
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
            "access_count": r[8],
            "failed_count": r[9],
            "suspicious_paths": json.loads(r[10] or "[]"),
            "status_counts": json.loads(r[11] or "{}"),
            "reasons": json.loads(r[12] or "[]"),
            "response_guides": json.loads(r[13] or "[]"),
        }
        for r in rows
    ]