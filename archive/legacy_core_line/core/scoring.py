from core.detection_rules import load_detection_rules

# NOTE:
# This scoring logic is provisional.
# Fine-grained calibration will be revisited after TimeSeries detection is introduced.

def get_signal_scores():
    rules = load_detection_rules()

    scores = {}

    for signal_name, config in rules.get("signals", {}).items():
        scores[signal_name] = config.get("score", 0)

    return scores


def calculate_score(signals: set[str], attacks: list[str]) -> int:
    rules = load_detection_rules()

    signal_scores = get_signal_scores()
    attack_rules = rules.get("attack_rules", {})
    max_score = rules.get("scoring", {}).get("max_score_per_ip", 10)

    attack_base_score = _calculate_attack_base_score(attacks, attack_rules)
    optional_bonus = _calculate_optional_bonus(signals, attacks, attack_rules)
    supporting_signal_score = _calculate_supporting_signal_score(
        signals=signals,
        attacks=attacks,
        attack_rules=attack_rules,
        signal_scores=signal_scores,
    )

    total_score = (
        attack_base_score
        + optional_bonus
        + supporting_signal_score
    )

    return min(total_score, max_score)


def _calculate_attack_base_score(
    attacks: list[str],
    attack_rules: dict,
) -> int:
    if not attacks:
        return 0

    return max(
        _get_attack_base_score(attack_rules, attack)
        for attack in attacks
    )


def _get_attack_base_score(attack_rules: dict, attack: str) -> int:
    config = attack_rules.get(attack, {})

    if "base_score" in config:
        return config["base_score"]

    # 旧YAML互換
    if "bonus_score" in config:
        return config["bonus_score"]

    return 0


def _calculate_optional_bonus(
    signals: set[str],
    attacks: list[str],
    attack_rules: dict,
) -> int:
    bonus = 0

    for attack in attacks:
        optional_signals = set(
            attack_rules.get(attack, {}).get("optional", [])
        )
        bonus += len(signals & optional_signals)

    return min(bonus, 2)


def _calculate_supporting_signal_score(
    signals: set[str],
    attacks: list[str],
    attack_rules: dict,
    signal_scores: dict,
) -> int:
    used_signals = set()

    for attack in attacks:
        config = attack_rules.get(attack, {})
        used_signals |= set(config.get("requires", []))
        used_signals |= set(config.get("optional", []))

    supporting_signals = signals - used_signals

    score = sum(
        signal_scores.get(signal, 0)
        for signal in supporting_signals
    )

    return min(score, 2)


def get_risk_level(score: int) -> str:
    rules = load_detection_rules()
    risk_levels = rules.get("risk_levels", {})

    if score >= risk_levels["high"]["min_score"]:
        return risk_levels["high"]["label"]

    if score >= risk_levels["medium"]["min_score"]:
        return risk_levels["medium"]["label"]

    return risk_levels["low"]["label"]