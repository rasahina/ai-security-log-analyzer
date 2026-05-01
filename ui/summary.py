from i18n import t


def extract_attack_types(df):
    attack_types = set()

    for value in df["attack_type"].dropna():
        for attack_type in str(value).split(", "):
            attack_types.add(attack_type)

    return attack_types


def generate_summary(df):
    high_count = len(df[df["risk_label"] == "HIGH"])
    medium_count = len(df[df["risk_label"] == "MEDIUM"])

    attack_types = extract_attack_types(df)

    if high_count > 0:
        messages = [
            t("summary_high_detected", count=high_count)
        ]

        if "Brute Force" in attack_types or "Coordinated Brute Force" in attack_types:
            messages.append(t("summary_brute_force"))

        if "Admin Access" in attack_types or "Suspicious Admin Timing" in attack_types:
            messages.append(t("summary_admin_access"))

        if "Scanner" in attack_types or "Reconnaissance" in attack_types or "Automated Scanner" in attack_types:
            messages.append(t("summary_scanner"))

        if "Burst Access" in attack_types:
            messages.append(t("summary_burst"))

        messages.append(t("summary_investigate"))
        return "\n\n".join(messages)

    if medium_count > 0:
        return "\n\n".join([
            t("summary_medium_detected", count=medium_count),
            t("summary_monitor"),
        ])

    return "\n\n".join([
        t("summary_no_risk"),
        t("summary_no_action"),
    ])