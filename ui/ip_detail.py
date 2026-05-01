import streamlit as st
import pandas as pd

from time_series_analysis import create_time_series
from ui.charts import create_timeline_chart
from ai_explainer import explain_detection
from security.ai_guard import build_safe_ai_payload, write_guard_logs
from config import AI_MODE

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

    # =========================
    # 🚨 Recommended Action
    # =========================
    st.markdown("### 🚨 Recommended Action")

    actions = selected["recommended_action"].split(" / ")
    for a in actions:
        st.markdown(f"- **{a}**")

    # =========================
    # 🛠 Response Guide
    # =========================
    st.markdown("### 🛠 Response Guide")

    guides = selected.get("response_guides", [])

    if not guides:
        st.info("No response guide available.")
    else:
        for item in guides:
            attack = item.get("attack_type")
            guide = item.get("guide", {})

            with st.container(border=True):
                st.markdown(f"**🔎 {attack}**")
                st.write(guide.get("plain_explanation", ""))

                if guide.get("immediate_actions"):
                    st.markdown("**🚨 Immediate Actions**")
                    for a in guide["immediate_actions"]:
                        st.markdown(f"- {a}")

                if guide.get("short_term_actions"):
                    with st.expander("Short-term Actions"):
                        for a in guide["short_term_actions"]:
                            st.markdown(f"- {a}")

                if guide.get("long_term_actions"):
                    with st.expander("Long-term Actions"):
                        for a in guide["long_term_actions"]:
                            st.markdown(f"- {a}")

                if guide.get("escalation"):
                    with st.expander("Escalation"):
                        for a in guide["escalation"]:
                            st.markdown(f"- {a}")

                advanced = guide.get("advanced_commands", {})
                if advanced.get("enabled"):
                    with st.expander("⚙️ Advanced Commands"):
                        st.warning(advanced.get("warning", ""))

                        for cmd in advanced.get("commands", []):
                            st.markdown(f"**{cmd.get('label', 'Command')}**")
                            if cmd.get("description"):
                                st.caption(cmd["description"])
                            command = cmd.get("command", "").replace("{ip}", selected_ip)
                            st.code(command, language="bash")

    # =========================
    # 🔧 Technical Details（まとめる）
    # =========================
    with st.expander("🔧 Technical Details"):
        if selected["suspicious_paths"]:
            st.markdown("**Suspicious Paths**")
            for path in selected["suspicious_paths"]:
                st.markdown(f"- `{path}`")

        if selected["reasons"]:
            st.markdown("**Signals**")
            for r in selected["reasons"]:
                st.markdown(f"- {r}")

        if selected["status_counts"]:
            st.markdown("**Status Counts**")
            st.json(selected["status_counts"])

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


    st.session_state.ai_mode = st.toggle("AI Mode", value=False)
    ai_enabled= st.session_state.ai_mode

    st.caption("AI Mode: local" if ai_enabled else "AI Mode: off")
    
    col1, col2 = st.columns([0.8, 0.2])

    with col2:
        if st.button("Clear Cache"):
            st.session_state.ai_cache = {}
            st.rerun()

    ai_payload, guard_logs = build_safe_ai_payload(selected.to_dict())
    write_guard_logs(guard_logs)
    st.session_state.ai_guard_logs = guard_logs

    if ai_enabled:
        if selected_ip not in st.session_state.ai_cache:
            with st.spinner(f"Analyzing {selected_ip}..."):
                st.session_state.ai_cache[selected_ip] = explain_detection(ai_payload, True)

        explanation = st.session_state.ai_cache[selected_ip]
    else:
        explanation = explain_detection(ai_payload, False)

    # explanation = explain_detection(ai_payload, True)

    st.info(explanation)
    st.caption(f"Cache size: {len(st.session_state.ai_cache)}")

    guard_logs = st.session_state.get("ai_guard_logs", [])

    with st.expander("🛡 AI Guard Log"):
        if not guard_logs:
            st.success("No AI Guard issues detected.")
        else:
            st.warning(f"AI Guard sanitized {len(guard_logs)} item(s).")
            st.dataframe(guard_logs, use_container_width=True, hide_index=True)


