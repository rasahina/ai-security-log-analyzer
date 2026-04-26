import streamlit as st
import requests
import pandas as pd

st.set_page_config(
page_title="AI Security Log Analyzer",
layout="wide"
)

st.title("AI Security Log Analyzer")
st.write("ログファイルをアップロードして、不審なアクセスを分析します。")

if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None

uploaded_file = st.file_uploader("Choose a log file", type=["log", "txt"])

if uploaded_file is not None:
    if st.button("Analyze File"):
        files = {
            "file": (
                uploaded_file.name,
                uploaded_file.getvalue(),
                "text/plain"
            )
        }

        response = requests.post(
            "http://127.0.0.1:8000/analyze-file",
            files=files
        )

        st.session_state.analysis_data = response.json()

if st.session_state.analysis_data is not None:
    data = st.session_state.analysis_data
    df = pd.DataFrame(data)

    # ここから下にSummary、表、IP Detailを書く

    df["risk_label"] = df["risk_level"].map({
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW"
    })

    display_columns = [
        "ip",
        "risk_label",
        "risk_score",
        "attack_type",
        "access_count",
        "failed_count",
        "suspicious_paths",
        "status_counts",
        "reasons",
    ]

    df = df[display_columns]
    df = df.sort_values(by="risk_score", ascending=False)


    st.subheader("Summary")

    total_ips = len(df)
    high_count = len(df[df["risk_label"] == "HIGH"])
    medium_count = len(df[df["risk_label"] == "MEDIUM"])
    low_count = len(df[df["risk_label"] == "LOW"])
    total_access = df["access_count"].sum()
    total_failed = df["failed_count"].sum()

    st.markdown("## Overview")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total IPs", total_ips)
    col2.metric("High Risk", high_count)
    col3.metric("Medium Risk", medium_count)
    col4.metric("Low Risk", low_count)
    col5.metric("Failed Requests", total_failed)
    st.subheader("Risk Distribution")
    risk_counts = df["risk_label"].value_counts()
    st.bar_chart(risk_counts)

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
    
    summary = generate_summary(df)
    st.markdown("## Security Summary")
    if len(df[df["risk_label"] == "HIGH"]) > 0:
        st.error(summary)
    elif len(df[df["risk_label"] == "MEDIUM"]) > 0:
        st.warning(summary)
    else:
        st.success(summary)
    st.markdown("## Analysis Table")
    st.dataframe(df, use_container_width=True)

    st.markdown("## High Risk IPs")

    high_risk_df = df[df["risk_label"] == "HIGH"]

    if high_risk_df.empty:
        st.success("No high-risk IPs detected.")
    else:
        st.dataframe(high_risk_df, use_container_width=True)

    st.markdown("## IP Detail")

    selected_ip = st.selectbox("Select IP", df["ip"])

    selected = df[df["ip"] == selected_ip].iloc[0]

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:
        st.metric("Risk Level", selected["risk_label"])
        st.metric("Risk Score", selected["risk_score"])
        st.metric("Attack Type", selected["attack_type"])

    with detail_col2:
        st.metric("Access Count", selected["access_count"])
        st.metric("Failed Count", selected["failed_count"])

    st.write("Suspicious Paths")
    st.code(selected["suspicious_paths"])

    st.write("Status Counts")
    st.json(selected["status_counts"])

    st.write("Reasons")
    st.write(selected["reasons"])