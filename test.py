from core.timeseries_signal_detector import detect_timeseries_signal_findings
from core.detection_rules import load_detection_rules
from datetime import datetime

rules = load_detection_rules()

events = [

    # ------------------------------
    # 10.0.0.1 → /login 200連打
    # ------------------------------
    {"timestamp": datetime(2026,5,1,10,0,0), "status": 200, "url": "/login"},
    {"timestamp": datetime(2026,5,1,10,0,5), "status": 200, "url": "/login"},
    {"timestamp": datetime(2026,5,1,10,0,10), "status": 200, "url": "/login"},
    {"timestamp": datetime(2026,5,1,10,0,15), "status": 200, "url": "/login"},
    {"timestamp": datetime(2026,5,1,10,0,20), "status": 200, "url": "/login"},

    # ------------------------------
    # 10.0.0.2 → 正常アクセス
    # ------------------------------
    {"timestamp": datetime(2026,5,1,10,1,0), "status": 200, "url": "/home"},
    {"timestamp": datetime(2026,5,1,10,2,0), "status": 200, "url": "/home"},
    {"timestamp": datetime(2026,5,1,10,3,0), "status": 200, "url": "/home"},

    # ------------------------------
    # 10.0.0.3 → 404連打
    # ------------------------------
    {"timestamp": datetime(2026,5,1,10,20,0), "status": 404, "url": "/aaa"},
    {"timestamp": datetime(2026,5,1,10,20,5), "status": 404, "url": "/bbb"},
    {"timestamp": datetime(2026,5,1,10,20,10), "status": 404, "url": "/ccc"},
    {"timestamp": datetime(2026,5,1,10,20,15), "status": 404, "url": "/ddd"},
    {"timestamp": datetime(2026,5,1,10,20,20), "status": 404, "url": "/eee"},

    # ------------------------------
    # 10.0.0.4 → ログイン失敗連打
    # ------------------------------
    {"timestamp": datetime(2026,5,1,11,0,0), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,11,0,5), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,11,0,10), "status": 403, "url": "/login"},
    {"timestamp": datetime(2026,5,1,11,0,15), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,11,0,20), "status": 403, "url": "/login"},

    # ------------------------------
    # 10.0.0.5 → adminアクセス
    # ------------------------------
    {"timestamp": datetime(2026,5,1,12,0,0), "status": 200, "url": "/admin"},
    {"timestamp": datetime(2026,5,1,12,0,5), "status": 401, "url": "/admin"},
    # 13:00 → 2つ目の high_failure_rate
    {"timestamp": datetime(2026,5,1,13,0,0), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,13,0,5), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,13,0,10), "status": 403, "url": "/login"},
    {"timestamp": datetime(2026,5,1,13,0,15), "status": 401, "url": "/login"},
    {"timestamp": datetime(2026,5,1,13,0,20), "status": 403, "url": "/login"},
]
findings = detect_timeseries_signal_findings(events, rules)

for f in findings:
    print(f)