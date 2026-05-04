# core/attack_detector.py

def detect_attacks(signals, rules):
    """
    Determine attack types from detected signals.

    Returns:
        list[str]
    """

    attack_rules = rules.get("attack_rules", {})
    fallback_rules = rules.get("fallback_rules", {})
    print("signals:", signals)

    detected_attacks = []

    for attack_name, config in attack_rules.items():
        required = set(config.get("requires", []))

        if required.issubset(signals):
            detected_attacks.append(attack_name)

    # --- fallback ---
    if not detected_attacks:
        if signals:
            return [fallback_rules["suspicious_activity"]["attack_type"]]
        else:
            return [fallback_rules["normal"]["attack_type"]]

    return detected_attacks