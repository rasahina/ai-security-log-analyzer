from datetime import datetime
from response_guides import get_guides


def get_risk_level(score):
    if score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"


def format_event(attack_type: str) -> str:
    if not attack_type or attack_type == "Normal":
        return "Normal activity"

    mapping = {
        "Automated Scanner": "Automated scanning activity",
        "Admin Access": "Admin access attempts",
        "Brute Force": "Brute-force login attempts",
        "Coordinated Brute Force": "Coordinated brute-force attack",
        "Suspicious Admin Timing": "Suspicious admin access timing",
    }

    types = attack_type.split(", ")

    formatted = [
        mapping.get(t, t)
        for t in types
    ]

    return " and ".join(formatted)



def classify_attack_type(reasons):
    attack_types = []

    if "repeated login attempts" in reasons:
        attack_types.append("Brute Force")

    if "admin access attempts" in reasons:
        attack_types.append("Admin Access")

    if "many 404 responses" in reasons:
        attack_types.append("Scanner")

    if "multiple suspicious paths" in reasons:
        attack_types.append("Reconnaissance")

    if "burst access detected" in reasons:
        attack_types.append("Burst Access")

    if "night time access" in reasons:
        attack_types.append("Anomalous Timing")
    
    if "coordinated brute force pattern" in reasons:
        attack_types.append("Coordinated Brute Force")

    if "suspicious admin access timing" in reasons:
        attack_types.append("Suspicious Admin Timing")

    if "automated scanning pattern" in reasons:
        attack_types.append("Automated Scanner")

    if not attack_types:
        if "high failure rate" in reasons:
            return "Suspicious Activity"
        return "Normal"
    
    
    return ", ".join(attack_types)

def simplify_attack_type(attack_type):
    priority_order = [
        "Coordinated Brute Force",
        "Automated Scanner",
        "Suspicious Admin Timing",
        "Brute Force",
        "Admin Access",
        "Scanner",
        "Reconnaissance",
        "Burst Access",
        "Anomalous Timing",
        "Suspicious Activity",
        "Normal",
    ]

    attack_types = attack_type.split(", ")

    sorted_types = sorted(
        attack_types,
        key=lambda x: (
            priority_order.index(x)
            if x in priority_order
            else 999
        )
    )

    return ", ".join(sorted_types[:2])

def detect_burst_access(timestamps, seconds=60, threshold=5):
    timestamps = sorted(timestamps)

    for i in range(len(timestamps)):
        count = 1

        for j in range(i + 1, len(timestamps)):
            delta = (timestamps[j] - timestamps[i]).total_seconds()

            if delta <= seconds:
                count += 1
            else:
                break

        if count >= threshold:
            return True

    return False

def recommend_action(risk_level, attack_type):
    actions = []

    if risk_level == "HIGH":
        actions.append("Investigate immediately")
    elif risk_level == "MEDIUM":
        actions.append("Monitor closely")
    else:
        actions.append("No immediate action required")

    if "Brute Force" in attack_type:
        actions.append("Check login attempts and consider temporary IP blocking")

    if "Admin Access" in attack_type:
        actions.append("Review admin access logs and verify authentication controls")

    if "Scanner" in attack_type or "Reconnaissance" in attack_type:
        actions.append("Review requested paths and consider rate limiting or blocking")

    if "Burst Access" in attack_type:
        actions.append("Apply rate limiting or temporary IP blocking")

    if "Anomalous Timing" in attack_type:
        actions.append("Review access time patterns and user behavior")

    if "Coordinated Brute Force" in attack_type:
        actions.append("Block source IP and review authentication logs immediately")

    if "Suspicious Admin Timing" in attack_type:
        actions.append("Verify admin activity and review privileged account usage")

    if "Automated Scanner" in attack_type:
        actions.append("Apply rate limiting and block scanning source if confirmed")

    return " / ".join(actions)

def simplify_recommended_action(action):
    priority_actions = [
        "Block source IP and review authentication logs immediately",
        "Apply rate limiting and block scanning source if confirmed",
        "Verify admin activity and review privileged account usage",
        "Investigate immediately",
        "Monitor closely",
        "No immediate action required",
    ]

    actions = action.split(" / ")

    selected_actions = []

    for priority_action in priority_actions:
        if priority_action in actions:
            selected_actions.append(priority_action)

    return " / ".join(selected_actions[:2])

def analyze_log_lines(lines):
    ip_counts = {}
    failed_counts = {}
    ip_scores = {}
    path_counts = {}
    suspicious_path_by_ip = {}
    status_counts = {}
    reasons_by_ip = {}
    timestamps_by_ip={}


    SUSPICIOUS_PATHS = [
        "/admin",
        "/login",
        "/phpmyadmin",
        "/wp-admin",
        "/.env",
        "/config",
        "/backup"
    ]

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) != 5:
            continue

        timestamp_str=parts[0]
        ip = parts[1]
        method = parts[2]
        url = parts[3]
        status = parts[4]

        timestamp=datetime.fromisoformat(timestamp_str)

        if ip not in ip_counts:
            ip_counts[ip] = 0
            failed_counts[ip] = 0
            ip_scores[ip] = 0
            path_counts[ip] = {}
            suspicious_path_by_ip[ip] = []
            status_counts[ip] = {}
            reasons_by_ip[ip] = []
            timestamps_by_ip[ip] = []
        
        timestamps_by_ip[ip].append(timestamp)

        ip_counts[ip] += 1

        if url not in path_counts[ip]:
            path_counts[ip][url] = 0
        path_counts[ip][url] += 1

        if status not in status_counts[ip]:
            status_counts[ip][status] = 0
        status_counts[ip][status] += 1

        if status in ["401", "403"]:
            failed_counts[ip] += 1
            ip_scores[ip] += 1

        if url in SUSPICIOUS_PATHS:
            if url not in suspicious_path_by_ip[ip]:
                suspicious_path_by_ip[ip].append(url)

    for ip in ip_counts:
        access_count = ip_counts[ip]
        failed_count = failed_counts[ip]
        failure_rate = failed_count / access_count if access_count > 0 else 0

        if failure_rate >= 0.5:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("high failure rate")

        if len(suspicious_path_by_ip[ip]) >= 2:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("multiple suspicious paths")

        if "/login" in path_counts[ip] and path_counts[ip]["/login"] >= 5:
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("repeated login attempts")

        if "404" in status_counts[ip] and status_counts[ip]["404"] >= 5:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("many 404 responses")

        if "/admin" in suspicious_path_by_ip[ip]:
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("admin access attempts")
        if detect_burst_access(timestamps_by_ip[ip]):
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("burst access detected")
        
        night_access = any(
            0 <= t.hour <5
            for t in timestamps_by_ip[ip]
        )

        if night_access:
            ip_scores[ip] += 2
            reasons_by_ip[ip].append("night time access")

        
        # 複合検知: Brute Force + Burst
        if (
            "repeated login attempts" in reasons_by_ip[ip]
            and "burst access detected" in reasons_by_ip[ip]
        ):
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("coordinated brute force pattern")

        # 複合検知: Admin + Night
        if (
            "admin access attempts" in reasons_by_ip[ip]
            and "night time access" in reasons_by_ip[ip]
        ):
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("suspicious admin access timing")

        # 複合検知: Scanner + Burst
        if (
            "many 404 responses" in reasons_by_ip[ip]
            and "burst access detected" in reasons_by_ip[ip]
        ):
            ip_scores[ip] += 3
            reasons_by_ip[ip].append("automated scanning pattern")

    results = []

    for ip in ip_counts:
        score = ip_scores[ip]
        level = get_risk_level(score)
        raw_attack_type = classify_attack_type(reasons_by_ip[ip])
        attack_type = simplify_attack_type(raw_attack_type)
        raw_action = recommend_action(level, raw_attack_type)
        recommended_action = simplify_recommended_action(raw_action)
        event = format_event(attack_type)
        response_guides = get_guides(attack_type)

        results.append({
            "ip": ip,
            "event": event,
            "risk_level": level,
            "risk_score": score,
            "attack_type": attack_type,
            "recommended_action": recommended_action,
            "response_guides": response_guides,
            "access_count": ip_counts[ip],
            "failed_count": failed_counts[ip],
            "suspicious_paths": suspicious_path_by_ip[ip],
            "status_counts": status_counts[ip],
            "reasons": reasons_by_ip[ip]
        })

    return results


def analyze_log_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return analyze_log_lines(lines)

def parse_log_lines(lines):
    parsed_logs = []

    for line in lines:
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split()

        if len(parts) != 5:
            continue

        parsed_logs.append({
            "timestamp": parts[0],
            "ip": parts[1],
            "method": parts[2],
            "url": parts[3],
            "status": int(parts[4])
        })

    return parsed_logs