import sqlite3
from datetime import datetime, timezone
from core.detection_rules import load_detection_rules


def sql_in_values(values):
    return ",".join(["?"] * len(values))

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
        error_message TEXT,
        FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
        FOREIGN KEY (file_id) REFERENCES analysis_files(id)
    )
    """)

    try:
        cur.execute("ALTER TABLE raw_logs ADD COLUMN file_id INTEGER")
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
            error_message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            file_id,
            log.get("log_type"),
            log.get("ip"),
            log.get("timestamp"),
            log.get("method"),
            log.get("url"),
            log.get("status"),
            log.get("error_message"),
        ))

    conn.commit()
    conn.close()


def get_ip_stats(run_id: int):
    rules = load_detection_rules()

    admin_paths = rules["paths"]["admin"]
    suspicious_paths = rules["paths"]["suspicious"]

    admin_placeholders = sql_in_values(admin_paths)
    suspicious_placeholders = sql_in_values(suspicious_paths)

    conn = get_connection()
    cur = conn.cursor()

    query = f"""
    SELECT
        ip,
        COUNT(*) AS access_count,
        SUM(CASE WHEN status IN (401, 403) THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN status = 404 THEN 1 ELSE 0 END) AS not_found_count,
        SUM(CASE WHEN url IN ({admin_placeholders}) THEN 1 ELSE 0 END) AS admin_path_count,
        SUM(CASE WHEN url IN ({suspicious_placeholders}) THEN 1 ELSE 0 END) AS suspicious_path_count,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen
    FROM raw_logs
    WHERE run_id = ?
      AND ip IS NOT NULL
    GROUP BY ip
    ORDER BY access_count DESC
    """

    params = (
        admin_paths
        + suspicious_paths
        + [run_id]
    )

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    return [
        {
            "ip": r[0],
            "access_count": r[1],
            "failed_count": r[2],
            "not_found_count": r[3],
            "admin_path_count": r[4],
            "suspicious_path_count": r[5],
            "first_seen": r[6],
            "last_seen": r[7],
            "failure_rate": (r[2] / r[1]) if r[1] else 0,
        }
        for r in rows
    ]

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

def get_ip_timestamps(run_id: int):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    SELECT ip, timestamp
    FROM raw_logs
    WHERE run_id = ?
      AND ip IS NOT NULL
    ORDER BY ip, timestamp
    """, (run_id,))

    rows = cur.fetchall()
    conn.close()

    timestamps_by_ip = {}

    for ip, ts in rows:
        try:
            t = datetime.fromisoformat(ts)
            if t.tzinfo is not None:
                t = t.replace(tzinfo=None)       
        except:
            continue

        if ip not in timestamps_by_ip:
            timestamps_by_ip[ip] = []

        timestamps_by_ip[ip].append(t)

    return timestamps_by_ip