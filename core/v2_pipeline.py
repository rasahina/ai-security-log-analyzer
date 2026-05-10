from core.detection_rules import load_detection_rules
from core.timeseries_signal_detector import detect_timeseries_signal_findings
from core.cluster_engine import build_signal_clusters
from core.cluster_relation_engine import resolve_signal_clusters
from core.attack_engine import build_attack_findings
from core.score_engine import calculate_attack_scores
from core.risk_engine import calculate_risk
from core.debug import debug_dump_json,debug_print
from core.v2_report_engine import build_detection_report
from core.config import OUTPUT_DIR
from core.output import save_output_json


def run_v2_pipeline(events_by_ip: dict) -> dict:
    rules = load_detection_rules("v2")
    signal_rules = load_detection_rules("signals")
    debug_print(
        "signal_rules keys:",
        signal_rules.keys(),
    )

    debug_print(
        "signal count:",
        len(signal_rules.get("signals", {})),
    )

    signal_findings_by_ip = {}

    for ip, events in events_by_ip.items():
        signal_findings_by_ip[ip] = detect_timeseries_signal_findings(
            events,
            signal_rules,
        )

    debug_dump_json("signal_findings_v2.json", signal_findings_by_ip)

    clusters_by_ip = build_signal_clusters(
        signal_findings_by_ip,
        rules,
    )
    debug_dump_json("signal_clusters_v2.json", clusters_by_ip)

    resolved_clusters_by_ip = resolve_signal_clusters(
        clusters_by_ip,
        rules,
    )
    debug_dump_json("cluster_relations_v2.json", resolved_clusters_by_ip)

    attacks_by_ip = build_attack_findings(
        resolved_clusters_by_ip,
        rules,
    )
    debug_dump_json("attacks_v2.json", attacks_by_ip)

    scores_by_ip = calculate_attack_scores(
        attacks_by_ip,
        rules,
    )
    debug_dump_json("scores_v2.json", scores_by_ip)

    risk_by_ip = calculate_risk(
        scores_by_ip,
        rules,
    )
    debug_dump_json("risk_v2.json", risk_by_ip)

    report = build_detection_report(risk_by_ip)
    save_output_json(
        "detection_report_v2.json",
        report,
    )

    return report