def calculate_attack_scores(attacks_by_ip: dict, rules: dict) -> dict:
    scores_by_ip = {}

    score_config = rules.get("score", {})
    global_score_cap_ratio = score_config.get("global_score_cap_ratio", 2.0)
    global_intensity_cap = score_config.get("global_intensity_cap", 1.0)

    for ip, attacks in attacks_by_ip.items():
        scores = []

        for attack in attacks:
            base_score = attack["base_score"]

            score_cap_ratio = (
                attack.get("score_cap_ratio_override")
                or global_score_cap_ratio
            )

            intensity_cap = (
                attack.get("intensity_cap_override")
                or global_intensity_cap
            )

            score_cap = base_score * score_cap_ratio
            normalized_intensity = min(
                attack["intensity"] / intensity_cap,
                1,
            )

            attack_score = (
                base_score
                + (score_cap - base_score)
                * normalized_intensity
                * attack["confidence"]
            )

            scores.append({
                "source_ip": ip,
                "attack_type": attack["attack_type"],
                "attack_start": attack["attack_start"],
                "attack_end": attack["attack_end"],
                "attack_score": attack_score,
            })

        scores_by_ip[ip] = scores

    return scores_by_ip