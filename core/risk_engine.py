def calculate_risk(scores_by_ip: dict, rules: dict) -> dict:
    risk_by_ip = {}

    thresholds = rules.get("risk", {}).get("risk_level_thresholds", {
        "low": 0,
        "medium": 3,
        "high": 6,
        "critical": 10,
    })

    for ip, scores in scores_by_ip.items():
        if not scores:
            overall_score = 0
            risk_level = "low"
            attacks = []
        else:
            overall_score = max(score["attack_score"] for score in scores)
            risk_level = _classify_risk(overall_score, thresholds)
            attacks = scores

        risk_by_ip[ip] = {
            "source_ip": ip,
            "overall_score": overall_score,
            "risk_level": risk_level,
            "attack_count": len(scores),
            "attacks": attacks,
        }

    return risk_by_ip


def _classify_risk(score: float, thresholds: dict) -> str:
    if score >= thresholds.get("critical", 10):
        return "critical"

    if score >= thresholds.get("high", 6):
        return "high"

    if score >= thresholds.get("medium", 3):
        return "medium"

    return "low"