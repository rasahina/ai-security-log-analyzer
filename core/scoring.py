from core.detection_rules import load_detection_rules


def get_signal_scores():
    rules = load_detection_rules()

    scores = {}

    for signal_name, config in rules.get("signals", {}).items():
        scores[signal_name] = config.get("score", 0)

    # 旧互換（あってもなくてもOK）
    for signal_name, config in rules.get("combined_signals", {}).items():
        scores[signal_name] = config.get("score", 0)

    return scores


def get_attack_bonus(attacks: list[str]) -> int:
    rules = load_detection_rules()
    attack_rules = rules.get("attack_rules", {})

    bonus = 0

    for attack in attacks:
        bonus += attack_rules.get(attack, {}).get("bonus_score", 0)

    return bonus


def calculate_score(signals: set[str], attacks: list[str]) -> int:
    rules = load_detection_rules()
    scores = get_signal_scores()

    max_score = rules.get("scoring", {}).get("max_score_per_ip", 10)

    signal_score = sum(scores.get(signal, 0) for signal in signals)
    attack_bonus = get_attack_bonus(attacks)

    total_score = signal_score + attack_bonus

    return min(total_score, max_score)


def get_risk_level(score: int) -> str:
    rules = load_detection_rules()
    risk_levels = rules.get("risk_levels", {})

    if score >= risk_levels["high"]["min_score"]:
        return risk_levels["high"]["label"]

    if score >= risk_levels["medium"]["min_score"]:
        return risk_levels["medium"]["label"]

    return risk_levels["low"]["label"]