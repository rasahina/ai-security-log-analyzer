def generate_summary(df):
    high = len(df[df["risk_label"] == "HIGH"])
    medium = len(df[df["risk_label"] == "MEDIUM"])

    brute_force = any(
        df["reasons"].apply(
            lambda x: "repeated login attempts" in x
        )
    )

    admin_attack = any(
        df["reasons"].apply(
            lambda x: "admin access attempts" in x
        )
    )

    scanning = any(
        df["reasons"].apply(
            lambda x: "many 404 responses" in x
        )
    )

    threat_parts = []

    if brute_force:
        threat_parts.append("a possible brute force attack")

    if admin_attack:
        threat_parts.append("unauthorized admin access attempts")

    if scanning:
        threat_parts.append("scanning activity")

    if high == 0 and medium == 0 and not threat_parts:
        return (
            "No significant threats were detected.\n\n"
            "No urgent action required."
        )

    summary = ""

    if high > 0:
        summary += (
            f"The analysis indicates that {high} "
            f"high-risk IPs were detected."
        )
    elif medium > 0:
        summary += (
            f"The analysis indicates that {medium} "
            f"medium-risk IPs were detected."
        )
    else:
        summary += "The analysis completed successfully."

    if threat_parts:
        if len(threat_parts) == 1:
            threat_text = threat_parts[0]
        elif len(threat_parts) == 2:
            threat_text = (
                threat_parts[0]
                + " and "
                + threat_parts[1]
            )
        else:
            threat_text = (
                ", ".join(threat_parts[:-1])
                + ", and "
                + threat_parts[-1]
            )

        summary += (
            "\n\nThe observed activity suggests "
            + threat_text
            + "."
        )

    if high > 0:
        summary += "\n\n⚠️ Immediate investigation is recommended."
    elif medium > 0:
        summary += "\n\nFurther monitoring is recommended."
    else:
        summary += "\n\nNo urgent action required."

    return summary 
