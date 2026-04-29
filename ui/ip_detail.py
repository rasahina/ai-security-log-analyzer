import streamlit as st
import pandas as pd

from time_series_analysis import create_time_series
from ui.charts import create_timeline_chart
from ai_explainer import explain_detection
from security.ai_guard import build_safe_ai_payload, write_guard_logs


def render_ip_detail(selected, selected_ip):
    st.markdown("## IP Detail")

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:
        risk = selected["risk_label"]
        if risk == "HIGH":
            st.markdown(f"### 🔴 Risk Level: **{risk}**")
        elif risk == "MEDIUM":
            st.markdown(f"### 🟠 Risk Level: **{risk}**")
        else:
            st.markdown(f"### 🟢 Risk Level: **{risk}**")

        st.metric("Risk Score", selected["risk_score"])
        st.markdown(f"### 🚨 {selected['event']}")

    with detail_col2:
        st.metric("Access Count", selected["access_count"])
        st.metric("Failed Count", selected["failed_count"])

    col_left, col_right = st.columns(2)

    with col_left:
        with st.expander("🔍 Suspicious Paths"):
            for path in selected["suspicious_paths"]:
                st.markdown(f"- `{path}`")

        st.markdown("### ⚡ Signals")
        for r in selected["reasons"]:
            st.markdown(f"- {r}")

    with col_right:
        with st.expander("📊 Status Counts"):
            st.json(selected["status_counts"])

    st.markdown("### Recommended Action")

    actions = selected["recommended_action"].split(" / ")

    for i, a in enumerate(actions):
        col_action, col_button = st.columns([0.8, 0.2])

        with col_action:
            st.markdown(f"- **{a}**")

        with col_button:
            if st.button("Run", key=f"action-{selected_ip}-{i}"):
                st.success(f"Triggered: {a}")


def render_selected_ip_timeline(selected_ip):
    st.markdown("### Selected IP Timeline")
    #履歴を表示の際にタイムラインがない場合出る。
    if not st.session_state.raw_logs:
        st.info("No timeline data available for this historical run.")
        return
    
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

        st.plotly_chart(
            fig_ip,
            use_container_width=True,
            key="selected_ip_timeline_chart"
        )

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


def render_ai_explanation(selected, selected_ip):
    st.markdown("## AI Explanation")

    col1, col2 = st.columns([0.8, 0.2])

    with col2:
        if st.button("Clear Cache"):
            st.session_state.ai_cache = {}
            st.rerun()

    if selected_ip not in st.session_state.ai_cache:
        with st.spinner(f"Analyzing {selected_ip}..."):
            ai_payload, guard_logs = build_safe_ai_payload(selected.to_dict())
            write_guard_logs(guard_logs)

            st.session_state.ai_cache[selected_ip] = explain_detection(ai_payload)
            st.session_state.ai_guard_logs = guard_logs
    else:
        st.session_state.ai_guard_logs = []

    explanation = st.session_state.ai_cache[selected_ip]

    st.info(explanation)
    st.caption(f"Cache size: {len(st.session_state.ai_cache)}")

    st.markdown("### AI Guard Log")

    guard_logs = st.session_state.get("ai_guard_logs", [])

    if not guard_logs:
        st.success("No AI Guard issues detected.")
    else:
        st.warning(f"AI Guard sanitized {len(guard_logs)} item(s).")
        st.dataframe(guard_logs, use_container_width=True, hide_index=True)

    st.caption(f"AI Guard events: {len(guard_logs)}")

