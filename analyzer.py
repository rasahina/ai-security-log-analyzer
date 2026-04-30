from datetime import datetime
from response_guides import get_guides
from parsers.log_parser import parse_log_lines
from correlation import correlate_logs
from scoring import SCORES


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

###検知ロジック関数化

def detect_brute_force(ip, path_counts, failed_count, access_count):
    reasons = []
    score = 0

    failure_rate = failed_count / access_count if access_count else 0

    if failure_rate >= 0.5:
        score += SCORES["high_failure_rate"]
        reasons.append("high failure rate")

    if "/login" in path_counts and path_counts["/login"] >= 5:
        score += SCORES["repeated_login"]
        reasons.append("repeated login attempts")

    return score, reasons

def detect_scanner(suspicious_paths_for_ip, status_counts_for_ip):
    score = 0
    reasons = []

    if len(suspicious_paths_for_ip) >= 2:
        score += SCORES["multiple_suspicious_paths"]
        reasons.append("multiple suspicious paths")

    if "404" in status_counts_for_ip and status_counts_for_ip["404"] >= 5:
        score += SCORES["many_404"]
        reasons.append("many 404 responses")

    return score, reasons


def detect_admin_access(suspicious_paths_for_ip):
    score = 0
    reasons = []

    if "/admin" in suspicious_paths_for_ip:
        score += SCORES["admin_access"]
        reasons.append("admin access attempts")

    return score, reasons

def detect_burst_access_rule(timestamps):
    score = 0
    reasons = []

    if detect_burst_access(timestamps):
        score += SCORES["burst_access"]
        reasons.append("burst access detected")

    return score, reasons

def detect_night_access(timestamps):
    score = 0
    reasons = []

    night_access = any(
        0 <= t.hour < 5
        for t in timestamps
    )

    if night_access:
        score += SCORES["night_access"]
        reasons.append("night time access")

    return score, reasons

def detect_combined_patterns(reasons):
    score = 0
    new_reasons = []

    if (
        "repeated login attempts" in reasons
        and "burst access detected" in reasons
    ):
        score += SCORES["coordinated_brute_force"]
        new_reasons.append("coordinated brute force pattern")

    if (
        "admin access attempts" in reasons
        and "night time access" in reasons
    ):
        score += SCORES["suspicious_admin_timing"]
        new_reasons.append("suspicious admin access timing")

    if (
        "many 404 responses" in reasons
        and "burst access detected" in reasons
    ):
        score += SCORES["automated_scanning"]
        new_reasons.append("automated scanning pattern")

    return score, new_reasons

def detect_access_error_correlation(ip, correlated_ips):
    score = 0
    reasons = []

    if ip in correlated_ips:
        score += SCORES["access_error_correlation"]
        reasons.append("access error correlation")

    return score, reasons

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

    parsed_logs = parse_log_lines(lines)
    correlations = correlate_logs(parsed_logs)
    correlated_ips = {c["ip"] for c in correlations}

    for log in parsed_logs:
        timestamp_str = log["timestamp"]
        ip = log["ip"]
        method = log["method"]
        url = log["url"]
        status = str(log["status"])
        try:
            timestamp = datetime.fromisoformat(timestamp_str)
        except Exception:
            continue

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


        score, reasons = detect_brute_force(
            path_counts[ip],
            failed_count,
            access_count
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

        score, reasons = detect_scanner(
            suspicious_path_by_ip[ip],
            status_counts[ip]
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

        score, reasons = detect_admin_access(
            suspicious_path_by_ip[ip]
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

        score, reasons = detect_burst_access_rule(
            timestamps_by_ip[ip]
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

        score, reasons = detect_night_access(
            timestamps_by_ip[ip]
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)


        #最後に実行
        score, reasons = detect_combined_patterns(reasons_by_ip[ip])

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

        score, reasons = detect_access_error_correlation(
            ip,
            correlated_ips
        )

        ip_scores[ip] += score
        reasons_by_ip[ip].extend(reasons)

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
