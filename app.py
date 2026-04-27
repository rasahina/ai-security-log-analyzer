import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
from time_series_analysis import create_time_series

#グラフ描画関数
def create_timeline_chart(time_df, title):
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=time_df["time_bucket"],
        y=time_df["access_count"],
        mode="lines",
        name="Access Count"
    ))

    fig.add_trace(go.Scatter(
        x=time_df["time_bucket"],
        y=time_df["failed_count"],
        mode="lines",
        name="Failed Count"
    ))

    anomaly_df = time_df[time_df["is_anomaly"]]

    fig.add_trace(go.Scatter(
        x=anomaly_df["time_bucket"],
        y=anomaly_df["access_count"],
        mode="markers",
        name="Anomaly",
        marker=dict(color="red", size=10),
        text=anomaly_df["anomaly_reason"],
        hovertemplate=(
            "Time: %{x}<br>"
            "Access Count: %{y}<br>"
            "Reason: %{text}<extra></extra>"
        )
    ))

    fig.update_layout(
        title=title,
        xaxis_title="Time",
        yaxis_title="Count",
        hovermode="x unified"
    )

    return fig


def highlight_risk(val):
    if val == "HIGH":
        return "background-color: #ff4d4d; color: white;"
    elif val == "MEDIUM":
        return "background-color: #ffa500; color: black;"
    elif val == "LOW":
        return "background-color: #4CAF50; color: white;"
    return ""


st.set_page_config(
page_title="AI Security Log Analyzer",
layout="wide"
)

st.title("AI Security Log Analyzer")
st.write("ログファイルをアップロードして、不審なアクセスを分析します。")

#初期化
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "raw_logs" not in st.session_state:
    st.session_state.raw_logs = None

uploaded_file = st.file_uploader("Choose a log file", type=["log", "txt"])

if st.button("Use Sample Log"):
    with open("data/sample.log", "r", encoding="utf-8") as f:
        text = f.read()

    response = requests.post(
        "http://127.0.0.1:8000/analyze",
        json={"log": text}
    )
    result = response.json()
    st.session_state.analysis_data = result["analysis"]
    st.session_state.raw_logs = result["raw_logs"]


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

        result = response.json()
        st.session_state.analysis_data = result["analysis"]
        st.session_state.raw_logs = result["raw_logs"]


if st.session_state.analysis_data is not None:
    data = st.session_state.analysis_data
    df = pd.DataFrame(data)

    # ここから下にSummary、表、IP Detailを書く
    #選択用変数初期化
    selected_ip_from_top = None
    selected_ip_from_table = None


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
        "recommended_action",
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

    st.markdown("## 🔝 Top Risky IPs")

    top_df = df.copy()

    top_df["failure_rate"] = (
        top_df["failed_count"] / top_df["access_count"]
    ).fillna(0)
        
    top_df["priority_score"] = (
        top_df["risk_score"] * 2
        + top_df["failure_rate"] * 5
    )

    display_top_df = top_df.head(10).reset_index(drop=True)

    event_top = st.dataframe(
        display_top_df[[
            "ip",
            "priority_score",
            "risk_score",
            "failure_rate",
            "attack_type",
            "access_count",
            "failed_count"
        ]],
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    selected_top_rows = event_top.selection.rows

    if selected_top_rows:
        selected_ip_from_top = display_top_df.iloc[selected_top_rows[0]]["ip"]
    else:
        selected_ip_from_top = None



    st.markdown("## Time Series Analysis")

    if st.session_state.raw_logs:
        raw_df = pd.DataFrame(st.session_state.raw_logs)
        time_df = create_time_series(raw_df, interval="5min")
        #Plotyグラフ描画
        fig = create_timeline_chart(
            time_df,
            "Access Timeline with Anomaly Points"
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No time-series data available.")

    st.markdown("## 🚨 Detected Anomalies")

    anomaly_df = time_df[time_df["is_anomaly"]]

    if anomaly_df.empty:
        st.success("No anomalies detected.")
    else:
        st.dataframe(anomaly_df, use_container_width=True)


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

    event = st.dataframe(
        df.style.map(highlight_risk, subset=["risk_label"]),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )

    selected_rows = event.selection.rows


    if selected_rows:
        selected_ip_from_table = df.iloc[selected_rows[0]]["ip"]
    else:
        selected_ip_from_table = None

    if selected_ip_from_top:
        selected_ip = selected_ip_from_top
    elif selected_ip_from_table:
        selected_ip = selected_ip_from_table
    else:
        selected_ip = df.iloc[0]["ip"]

    selected = df[df["ip"] == selected_ip].iloc[0]



    st.markdown("## High Risk IPs")

    high_risk_df = df[df["risk_label"] == "HIGH"]

    if high_risk_df.empty:
        st.success("No high-risk IPs detected.")
    else:
        st.dataframe(high_risk_df, use_container_width=True)


    if selected_ip:
        selected = df[df["ip"] == selected_ip].iloc[0]
    elif selected_rows:
        selected = df.iloc[selected_rows[0]]
    else:
        selected = df.iloc[0]



    st.markdown("## IP Detail")

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:
        #st.metric("Risk Level", selected["risk_label"])
        risk = selected["risk_label"]
        if risk == "HIGH":
            st.markdown(f"### 🔴 Risk Level: **{risk}**")
        elif risk == "MEDIUM":
            st.markdown(f"### 🟠 Risk Level: **{risk}**")
        else:
            st.markdown(f"### 🟢 Risk Level: **{risk}**")
        #################################################
        st.metric("Risk Score", selected["risk_score"])
        #st.metric("Attack Type", selected["attack_type"])
        st.write("Attack Type")
        st.info(selected["attack_type"])

    with detail_col2:
        st.metric("Access Count", selected["access_count"])
        st.metric("Failed Count", selected["failed_count"])

    st.write("Suspicious Paths")
    st.code(selected["suspicious_paths"])

    st.write("Status Counts")
    st.json(selected["status_counts"])

    st.write("Reasons")
    st.write(selected["reasons"])

    st.write("Recommended Action")
    st.info(selected["recommended_action"])

    st.markdown("### Selected IP Timeline")

    raw_df = pd.DataFrame(st.session_state.raw_logs)
    time_df = create_time_series(raw_df, interval="1min")

    ip_time_df = time_df[time_df["ip"] == selected_ip]

    if ip_time_df.empty:
        st.info("No timeline data for this IP.")
    else:
        fig_ip = create_timeline_chart(
            ip_time_df,
            f"Timeline for {selected_ip}"
        )

        st.plotly_chart(fig_ip, use_container_width=True)


    st.markdown("### Selected IP Anomalies")

    ip_anomaly_df = ip_time_df[ip_time_df["is_anomaly"]]

    if ip_anomaly_df.empty:
        st.success("No anomalies detected for this IP.")
    else:
        st.dataframe(
            ip_anomaly_df[[
                "time_bucket",
                "ip",
                "access_count",
                "failed_count",
                "failure_rate",
                "risk_signal_count",
                "anomaly_reason"
            ]],
            use_container_width=True,
            hide_index=True
        )