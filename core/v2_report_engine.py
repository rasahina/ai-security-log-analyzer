from datetime import datetime, UTC


def build_finding_id(
    source_ip: str,
    attack_type: str,
    attack_start,
) -> str:

    ts = attack_start.strftime(
        "%Y%m%dT%H%M%S"
    )

    return (
        f"v2-{source_ip}-"
        f"{attack_type}-{ts}"
    )

def build_ip_report_time_range(attacks: list) -> dict | None:

    if not attacks:
        return None

    starts = [
        attack["attack_start"]
        for attack in attacks
    ]

    ends = [
        attack["attack_end"]
        for attack in attacks
    ]

    return {
        "start": min(starts),
        "end": max(ends),
    }
def build_detection_report(risk_by_ip: dict) -> dict:
    ip_reports = []

    for ip_data in risk_by_ip.values():

        findings = []

        for attack in ip_data.get("attacks", []):

            finding_id = build_finding_id(
                attack["source_ip"],
                attack["attack_type"],
                attack["attack_start"],
            )

            findings.append({
                "finding_id": finding_id,
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
            "time_range": build_ip_report_time_range(
                ip_data.get("attacks", [])
            ),
            "findings": findings,
        })

    return {
        "schema_version": "v2_minimal_0.1",
        "generated_at": datetime.now(UTC).isoformat(),
        "ip_reports": ip_reports,
    }