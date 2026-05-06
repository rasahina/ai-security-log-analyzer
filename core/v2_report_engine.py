from datetime import datetime


def build_detection_report(risk_by_ip: dict) -> dict:
    ip_reports = []

    for ip_data in risk_by_ip.values():

        findings = []

        for attack in ip_data.get("attacks", []):

            findings.append({
                "finding_type": (
                    "suspicious_activity"
                    if attack["attack_type"] == "suspicious_activity"
                    else "confirmed_attack"
                ),
                "attack_type": attack["attack_type"],
                "source_ip": attack["source_ip"],
                "score": attack["attack_score"],
                "time_range": {
                    "start": attack["attack_start"],
                    "end": attack["attack_end"],
                },
            })

        ip_reports.append({
            "source_ip": ip_data["source_ip"],
            "overall_score": ip_data["overall_score"],
            "risk_level": ip_data["risk_level"],
            "attack_count": ip_data["attack_count"],
            "findings": findings,
        })

    return {
        "schema_version": "v2_minimal_0.1",
        "generated_at": datetime.utcnow().isoformat(),
        "ip_reports": ip_reports,
    }