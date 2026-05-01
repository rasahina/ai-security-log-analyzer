import streamlit as st
import pandas as pd
from time_series_analysis import create_time_series


from ai_explainer import explain_detection
from security.ai_guard import build_safe_ai_payload, write_guard_logs
from ui.charts import create_timeline_chart
from client.api_client import analyze_text_log, analyze_uploaded_file
from client.api_client import get_history, get_history_detail
from ui.summary import generate_summary
from ui.ip_detail import (
    render_ip_detail,
    render_selected_ip_timeline,
    render_ai_explanation,
    )


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

st.markdown("""
<style>
html, body, [class*="css"]  {
    font-size: 13px;
}
.block-container {
    padding-top: 1rem;
    padding-bottom: 1rem;
}
</style>
""", unsafe_allow_html=True)


st.title("AI Security Log Analyzer")
st.write("ログファイルをアップロードして、不審なアクセスを分析します。")

#初期化
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "raw_logs" not in st.session_state:
    st.session_state.raw_logs = None
if "ai_cache" not in st.session_state:
    st.session_state.ai_cache = {}
if "ai_guard_logs" not in st.session_state:
    st.session_state.ai_guard_logs = []


uploaded_file = st.file_uploader("Choose a log file", type=["log", "txt"])

if st.button("Use Sample Log"):
    st.session_state.ai_cache = {}
    st.session_state.ai_guard_logs = []
    with open("data/sample.log", "r", encoding="utf-8") as f:
        text = f.read()
    result = analyze_text_log(text)
    st.session_state.analysis_data = result["analysis"]
    st.session_state.raw_logs = result["raw_logs"]


if uploaded_file is not None:
    if st.button("Analyze File"):
        st.session_state.ai_cache = {}
        st.session_state.ai_guard_logs = []
        result = analyze_uploaded_file(uploaded_file)
        st.session_state.analysis_data = result["analysis"]
        st.session_state.raw_logs = result["raw_logs"]

st.markdown("## History")

if st.button("Load History"):
    st.session_state.history = get_history()

if "history" in st.session_state and st.session_state.history:
    history = st.session_state.history

    run_options = {
        f"Run {r['id']} | {r['created_at']} | HIGH:{r['high_count']} MED:{r['medium_count']} LOW:{r['low_count']}": r["id"]
        for r in history
    }

    selected_run_label = st.selectbox(
        "Select past analysis",
        list(run_options.keys())
    )

    if st.button("Load Selected Run"):
        run_id = run_options[selected_run_label]
        detail = get_history_detail(run_id)
        data = detail["detections"]
        # 足りないカラムを補完
        for item in data:
            item.setdefault("access_count", 0)
            item.setdefault("failed_count", 0)
            item.setdefault("suspicious_paths", [])
            item.setdefault("status_counts", {})
            item.setdefault("reasons", [])
            item.setdefault("response_guides", [])

        st.session_state.analysis_data = data
        st.session_state.raw_logs = []
        st.session_state.ai_cache = {}
        st.session_state.ai_guard_logs = []

        st.success(f"Loaded Run ID: {run_id}")


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
        "event",
        "risk_label",
        "risk_score",
        "attack_type",
        "access_count",
        "recommended_action",
        "failed_count",
        "suspicious_paths",
        "status_counts",
        "reasons",
        "response_guides",
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
    #AVOID 0 Division
    top_df["failure_rate"] = (
        top_df["failed_count"] / top_df["access_count"]
    ).replace([float("inf"), -float("inf")], 0).fillna(0)

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

        #st.plotly_chart(fig, use_container_width=True)
        st.plotly_chart(
            fig,
            use_container_width=True,
            key="overall_timeline_chart"
        )
        st.markdown("## 🚨 Detected Anomalies")

        anomaly_df = time_df[time_df["is_anomaly"]]

        if anomaly_df.empty:
            st.success("No anomalies detected.")
        else:
            st.dataframe(anomaly_df, use_container_width=True)


    else:
        st.info("No time-series data available.")

   
    summary = generate_summary(df)

    st.markdown("## Security Summary")
    if len(df[df["risk_label"] == "HIGH"]) > 0:
        st.error(summary)
    elif len(df[df["risk_label"] == "MEDIUM"]) > 0:
        st.warning(summary)
    else:
        st.success(summary)


    df_display = df[[
        "ip",
        "event",
        "risk_label",
        "risk_score",
        "attack_type",
        "access_count",
        "recommended_action",
    ]]

    st.markdown("## Filters")

    risk_filter = st.selectbox(
        "Filter by risk level",
        ["ALL", "HIGH", "MEDIUM", "LOW"]
    )

    if risk_filter != "ALL":
        df_view = df_display[df_display["risk_label"] == risk_filter]
    else:
        df_view = df_display


    st.markdown("## Analysis Table")

    event = st.dataframe(
        df_view.style.map(highlight_risk, subset=["risk_label"]),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )


    st.markdown("### Export")

    #csv = df.to_csv(index=False).encode("utf-8")
    csv = df_view.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download analysis as CSV",
        data=csv,
        file_name="security_analysis.csv",
        mime="text/csv"
    )


    selected_rows = event.selection.rows


    if selected_rows:
        selected_ip_from_table = df_view.iloc[selected_rows[0]]["ip"]
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


### IP DETAIL
    render_ip_detail(selected, selected_ip)
    with st.expander("📈 Timeline Analysis"):
        render_selected_ip_timeline(selected_ip)
    with st.expander("🤖 AI Explanation(for deeper analysis)"):
        render_ai_explanation(selected, selected_ip)
