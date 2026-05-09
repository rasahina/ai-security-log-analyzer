from datetime import datetime
from core.response_guides import get_guides
from core.correlation import correlate_logs
from core.response_guides import (
    get_guides,
    format_event,
    format_recommended_action,
)
from data_layer.database import get_ip_stats, get_ip_timestamps
from data_layer.analysis_repository import (
    create_run_from_text,
    create_run_from_files,
    build_log_stats,
)
from core.detection_rules import load_detection_rules
from core.scoring import calculate_score, get_risk_level
from core.attack_detector import detect_attacks
from data_layer.database import update_analysis_run_summary
from data_layer.database import get_ip_stats, get_ip_events
from core.timeseries_signal_detector import detect_timeseries_signal_findings
from core.debug import debug_dump_json
from core.cluster_engine import build_signal_clusters
from core.attack_engine import build_attack_findings
from core.score_engine import calculate_attack_scores
from core.risk_engine import calculate_risk
from core.cluster_relation_engine import resolve_signal_clusters


def analyze_run_from_db(run_id: int):
    rules = load_detection_rules()
    ip_stats = get_ip_stats(run_id)
    #timestamps_by_ip = get_ip_timestamps(run_id)
    events_by_ip = get_ip_events(run_id)

    results = []
    debug_signals_by_ip = {}

    for stat in ip_stats:
        ip = stat["ip"]

        events= events_by_ip.get(ip,[])
        signal_findings = detect_timeseries_signal_findings(events, rules)
        debug_signals_by_ip[ip] = signal_findings
        signals = {finding["name"] for finding in signal_findings}
        #signals = detect_timeseries_signals(events, rules)
        attacks = detect_attacks(signals, rules)

        score = calculate_score(signals, attacks)
        level = get_risk_level(score)

        attack_type = ", ".join(attacks) if attacks else "Normal"
        response_guides = get_guides(attack_type)

        results.append({
            "ip": ip,
            "event": format_event(response_guides),
            "risk_level": level,
            "risk_score": score,
            "attack_type": attack_type,
            "recommended_action": format_recommended_action(response_guides, level),
            "access_count": stat.get("access_count", 0),
            "failed_count": stat.get("failed_count", 0),
            "suspicious_paths": [],
            "status_counts": {},
            "signals": sorted(list(signals)),
            "signal_findings": [
                {
                    **finding,
                    "matched_start": finding["matched_start"].isoformat(),
                    "matched_end": finding["matched_end"].isoformat(),
                    "window_start": finding["window_start"].isoformat(),
                    "window_end": finding["window_end"].isoformat(),
                }
                for finding in signal_findings
            ],
            "attacks": attacks,
            "response_guides": response_guides,
        })
    debug_dump_json("debug_signal.json", debug_signals_by_ip)
    clusters_by_ip = build_signal_clusters(debug_signals_by_ip, rules)
    debug_dump_json("debug_cluster.json", clusters_by_ip)

    resolved_clusters_by_ip = resolve_signal_clusters(
        clusters_by_ip,
        rules,
    )

    debug_dump_json(
        "debug_cluster_relation.json",
        resolved_clusters_by_ip,
    )

    attacks_by_ip = build_attack_findings(
        resolved_clusters_by_ip,
        rules,
    )
    debug_dump_json("debug_attack.json", attacks_by_ip)
    scores_by_ip = calculate_attack_scores(attacks_by_ip, rules)
    debug_dump_json("debug_score.json", scores_by_ip)
    risk_by_ip = calculate_risk(scores_by_ip, rules)
    debug_dump_json("debug_risk.json", risk_by_ip)

    return results

def analyze_single_file(text: str, source: str):
    run_id, parsed_logs, skipped_logs = create_run_from_text(
        text=text,
        source=source,
    )

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    return {
        "run_id": run_id,
        "analysis": results,
        "raw_logs": parsed_logs,
        "skipped_logs": skipped_logs,
        "log_stats": build_log_stats(parsed_logs, skipped_logs),
    }


def analyze_multiple_files(files: list[dict]):
    run_id, raw_logs, skipped_logs = create_run_from_files(files)

    results = analyze_run_from_db(run_id)
    update_analysis_run_summary(run_id, results)

    return {
        "run_id": run_id,
        "analysis": results,
        "raw_logs": raw_logs,
        "skipped_logs": skipped_logs,
        "log_stats": build_log_stats(raw_logs, skipped_logs),
    }