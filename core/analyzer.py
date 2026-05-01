from datetime import datetime
from core.response_guides import get_guides
from data_layer.log_parser import parse_log_lines
from core.correlation import correlate_logs
from core.scoring import  calculate_score
from core.response_guides import get_guides, get_attack_type_priority
from data_layer.database import get_ip_stats, get_ip_timestamps
from core.detection_rules import load_detection_rules
from core.scoring import calculate_score, get_risk_level, signals_to_reasons


def get_risk_level(score):
    if score >= 8:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    return "LOW"


def format_event(response_guides):
    if not response_guides:
        return "Normal activity"

    titles = [
        g["guide"].get("title", "")
        for g in response_guides
    ]

    return " / ".join(titles)



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

    if "access error correlation" in reasons:
        attack_types.append("Access Error Correlation")

    if not attack_types:
        if "high failure rate" in reasons:
            return "Suspicious Activity"
        return "Normal"
    
    
    return ", ".join(attack_types)

def simplify_attack_type(attack_type):
    priority_order = get_attack_type_priority()
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

    left = 0

    for right in range(len(timestamps)):
        while (timestamps[right] - timestamps[left]).total_seconds() > seconds:
            left += 1

        if right - left + 1 >= threshold:
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

def detect_brute_force(path_counts, failed_count, access_count):
    return 0, []

def detect_scanner(suspicious_paths_for_ip, status_counts_for_ip):

    return 0, []


def detect_admin_access(path_counts_for_ip, status_counts_for_ip):

    return 0, []

def detect_burst_access_rule(timestamps):
    return 0, []

def detect_night_access(timestamps):
    return 0, []

def detect_combined_patterns(reasons):
    return 0, []

def detect_access_error_correlation(ip, correlated_ips):
    return 0, []

def signals_to_reasons(signals):
    mapping = {
        "high_failure_rate": "high failure rate",
        "repeated_login": "repeated login attempts",
        "multiple_suspicious_paths": "multiple suspicious paths",
        "many_404": "many 404 responses",
        "admin_access": "admin access attempts",
        "burst_access": "burst access detected",
        "night_access": "night time access",
        "coordinated_brute_force": "coordinated brute force pattern",
        "suspicious_admin_timing": "suspicious admin access timing",
        "automated_scanning": "automated scanning pattern",
        "access_error_correlation": "access error correlation",
    }

    return [mapping[s] for s in signals if s in mapping]



def analyze_run_from_db(run_id: int):
    rules = load_detection_rules()
    signals_config = rules.get("signals", {})
    combined_config = rules.get("combined_signals", {})

    ip_stats = get_ip_stats(run_id)
    results = []
    timestamps_by_ip = get_ip_timestamps(run_id)

    for stat in ip_stats:
        ip = stat["ip"]
        access_count = stat["access_count"]
        failed_count = stat["failed_count"]
        failure_rate = stat["failure_rate"]

        signals = set()

        high_failure_rule = signals_config["high_failure_rate"]
        if (
            access_count >= high_failure_rule["min_access_count"]
            and failure_rate >= high_failure_rule["failure_rate"]
        ):
            signals.add("high_failure_rate")

        repeated_login_rule = signals_config["repeated_login"]
        if failed_count >= repeated_login_rule["min_failed_count"]:
            signals.add("repeated_login")

        suspicious_rule = signals_config["multiple_suspicious_paths"]
        if stat["suspicious_path_count"] >= suspicious_rule["min_count"]:
            signals.add("multiple_suspicious_paths")

        many_404_rule = signals_config["many_404"]
        if stat["not_found_count"] >= many_404_rule["min_count"]:
            signals.add("many_404")

        admin_rule = signals_config["admin_access"]
        if stat["admin_path_count"] >= admin_rule.get("min_count", 1):
            signals.add("admin_access")

        timestamps = timestamps_by_ip.get(ip, [])

        burst_rule = signals_config["burst_access"]
        if detect_burst_access(
            timestamps,
            seconds=burst_rule["seconds"],
            threshold=burst_rule["threshold"],
        ):
            signals.add("burst_access")

        night_rule = signals_config["night_access"]
        start_hour = night_rule["start_hour"]
        end_hour = night_rule["end_hour"]

        if any(start_hour <= t.hour < end_hour for t in timestamps):
            signals.add("night_access")

        for signal_name, config in combined_config.items():
            required = set(config.get("requires", []))

            if required.issubset(signals):
                signals.add(signal_name)

                for suppressed in config.get("suppress", []):
                    signals.discard(suppressed)

        score = calculate_score(signals)
        level = get_risk_level(score)

        reasons = signals_to_reasons(signals)

        raw_attack_type = classify_attack_type(reasons)
        attack_type = simplify_attack_type(raw_attack_type)

        raw_action = recommend_action(level, raw_attack_type)
        recommended_action = simplify_recommended_action(raw_action)

        response_guides = get_guides(attack_type)
        event = format_event(response_guides)

        results.append({
            "ip": ip,
            "event": event,
            "risk_level": level,
            "risk_score": score,
            "attack_type": attack_type,
            "recommended_action": recommended_action,
            "access_count": access_count,
            "failed_count": failed_count,
            "suspicious_paths": [],
            "status_counts": {},
            "signals": list(signals),
            "reasons": reasons,
            "response_guides": response_guides,
        })

    return results