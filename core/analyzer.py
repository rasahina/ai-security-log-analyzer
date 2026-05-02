from datetime import datetime
from core.response_guides import get_guides
from data_layer.log_parser import parse_log_lines
from core.correlation import correlate_logs
from core.scoring import  calculate_score
from core.response_guides import get_guides, get_attack_type_priority
from data_layer.database import get_ip_stats, get_ip_timestamps
from core.detection_rules import load_detection_rules
from core.scoring import calculate_score, get_risk_level
from core.signal_detector import detect_signals
from core.attack_detector import detect_attacks


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




def analyze_run_from_db(run_id: int):
    rules = load_detection_rules()
    #signals_config = rules.get("signals", {})
    #combined_config = rules.get("combined_signals", {})

    ip_stats = get_ip_stats(run_id)
    results = []
    timestamps_by_ip = get_ip_timestamps(run_id)

    for stat in ip_stats:
        ip = stat["ip"]
        access_count = stat["access_count"]
        failed_count = stat["failed_count"]
        #failure_rate = stat["failure_rate"]
        timestamps = timestamps_by_ip.get(ip, [])
        signals = detect_signals(stat, timestamps, rules)
        attacks = detect_attacks(signals, rules)
        attack_type = ", ".join(attacks) if attacks else "Normal"

        score = calculate_score(signals,attacks)
        level = get_risk_level(score)

        raw_action = recommend_action(level, attack_type)
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
            #Raw Facts
            "access_count": access_count,
            "failed_count": failed_count,
            "suspicious_paths": [],
            "status_counts": {},
            #layer outputs
            "signals": list(signals),
            "attacks": attacks,
            "response_guides": response_guides,
        })

    return results



# =========================
# Entry points / use cases
# =========================
def analyze_single_file(text: str, source: str):
    from data_layer.log_parser import parse_log_lines
    from data_layer.database import save_analysis_run, save_raw_logs, update_analysis_run_summary

    lines = text.splitlines()

    parsed_logs, skipped_logs = parse_log_lines(lines)

    run_id = save_analysis_run([], source=source)
    save_raw_logs(run_id, parsed_logs)

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    total_count = len(parsed_logs) + len(skipped_logs)
    parsed_count = len(parsed_logs)
    skipped_count = len(skipped_logs)

    return {
        "run_id": run_id,
        "analysis": results,
        "raw_logs": parsed_logs,
        "skipped_logs": skipped_logs,
        "log_stats": {
            "total": total_count,
            "parsed": parsed_count,
            "skipped": skipped_count,
        },
    }

def analyze_multiple_files(files: list[dict]):
    from data_layer.log_parser import parse_log_lines
    from data_layer.database import (
        save_analysis_run,
        save_raw_logs,
        update_analysis_run_summary,
        create_analysis_file
    )

    run_id = save_analysis_run([], source="multi-upload")

    all_raw_logs = []
    all_skipped_logs = []
    total_count = 0
    parsed_count = 0
    skipped_count = 0

    for f in files:
        file_name = f["file_name"]
        text = f["text"]

        lines = text.splitlines()
        parsed_logs, skipped_logs = parse_log_lines(lines)
        total_count += len(parsed_logs) + len(skipped_logs)
        parsed_count += len(parsed_logs)
        skipped_count += len(skipped_logs)
        file_id = create_analysis_file(run_id, file_name)

        save_raw_logs(run_id, parsed_logs, file_id=file_id)

        all_raw_logs.extend(parsed_logs)
        all_skipped_logs.extend(skipped_logs)

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    return {
        "run_id": run_id,
        "analysis": results,
        "raw_logs": all_raw_logs,
        "skipped_logs": all_skipped_logs,
        "log_stats": {
            "total": total_count,
            "parsed": parsed_count,
            "skipped": skipped_count,
        },
    }