from detection_rules import load_detection_rules


def get_signal_scores():
    rules = load_detection_rules()

    scores = {}

    for signal_name, config in rules.get("signals", {}).items():
        scores[signal_name] = config.get("score", 0)

    for signal_name, config in rules.get("combined_signals", {}).items():
        scores[signal_name] = config.get("score", 0)

    return scores



def calculate_score(signals: set[str]) -> int:
    rules = load_detection_rules()
    scores = get_signal_scores()

    max_score = rules.get("scoring", {}).get("max_score_per_ip", 10)

    score = sum(scores.get(signal, 0) for signal in signals)
    return min(score, max_score)


def get_risk_level(score: int) -> str:
    rules = load_detection_rules()
    risk_levels = rules.get("risk_levels", {})

    if score >= risk_levels["high"]["min_score"]:
        return risk_levels["high"]["label"]

    if score >= risk_levels["medium"]["min_score"]:
        return risk_levels["medium"]["label"]

    return risk_levels["low"]["label"]


def signals_to_reasons(signals: set[str]) -> list[str]:
    rules = load_detection_rules()

    reasons = []

    for signal in signals:
        if signal in rules.get("signals", {}):
            reasons.append(rules["signals"][signal].get("reason", signal))

        elif signal in rules.get("combined_signals", {}):
            reasons.append(rules["combined_signals"][signal].get("reason", signal))

    return reasons