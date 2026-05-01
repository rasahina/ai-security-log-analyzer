import streamlit as st
import pandas as pd
from time_series_analysis import create_time_series
from i18n import t, translate_attack_type, translate_action, translate_anomaly_reason, translate_signals
import plotly.express as px

from ai_explainer import explain_detection
from security.ai_guard import build_safe_ai_payload, write_guard_logs
from client.api_client import analyze_text_log, analyze_uploaded_file
from client.api_client import get_history, get_history_detail

from ui.components import (
    create_timeline_chart,
    generate_summary,
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


st.title(t("app_title"))
st.write(t("app_description"))

#初期化
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "raw_logs" not in st.session_state:
    st.session_state.raw_logs = None
if "ai_cache" not in st.session_state:
    st.session_state.ai_cache = {}
if "ai_guard_logs" not in st.session_state:
    st.session_state.ai_guard_logs = []


uploaded_file = st.file_uploader(t("choose_log_file"), type=["log", "txt"])

if st.button(t("use_sample_log")):
    st.session_state.ai_cache = {}
    st.session_state.ai_guard_logs = []
    with open("data/sample.log", "r", encoding="utf-8") as f:
        text = f.read()
    result = analyze_text_log(text)
    st.session_state.analysis_data = result["analysis"]
    st.session_state.raw_logs = result["raw_logs"]


if uploaded_file is not None:
    if st.button(t("analyze_file")):
        st.session_state.ai_cache = {}
        st.session_state.ai_guard_logs = []
        result = analyze_uploaded_file(uploaded_file)
        st.session_state.analysis_data = result["analysis"]
        st.session_state.raw_logs = result["raw_logs"]

st.markdown(f"## {t('history')}")

if st.button(t("load_history")):
    st.session_state.history = get_history()

if "history" in st.session_state and st.session_state.history:
    history = st.session_state.history

    run_options = {
        f"Run {r['id']} | {r['created_at']} | HIGH:{r['high_count']} MED:{r['medium_count']} LOW:{r['low_count']}": r["id"]
        for r in history
    }

    selected_run_label = st.selectbox(
        t("Select_past_analysis"),
        list(run_options.keys())
    )

    if st.button(t("load_selected_run")):
        run_id = run_options[selected_run_label]
        detail = get_history_detail(run_id)
        data = detail["detections"]
        # 足りないカラムを補完
        for item in data:
            item.setdefault("access_count", 0)
            item.setdefault("failed_count", 0)
            item.setdefault("suspicious_paths", [])
            item.setdefault("status_counts", {})
            item.setdefault("signals", [])
            item.setdefault("reasons", [])
            item.setdefault("response_guides", [])

        st.session_state.analysis_data = data
        st.session_state.raw_logs = []
        st.session_state.ai_cache = {}
        st.session_state.ai_guard_logs = []

        st.success(f"{t('loaded_run_id')}: {run_id}")


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
        "signals",
        "reasons",
        "response_guides",
    ]

    df = df[display_columns]
    df = df.sort_values(by="risk_score", ascending=False)
    df["attack_type_jp"] = df["attack_type"].apply(translate_attack_type)
    df["recommended_action_jp"] = df["recommended_action"].apply(translate_action)
    df["signals_jp"] = df["signals"].apply(translate_signals)


    total_ips = len(df)
    high_count = len(df[df["risk_label"] == "HIGH"])
    medium_count = len(df[df["risk_label"] == "MEDIUM"])
    low_count = len(df[df["risk_label"] == "LOW"])
    total_access = df["access_count"].sum()
    total_failed = df["failed_count"].sum()

    st.markdown(f"## {t('overview')}")

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(t("total_ips"), total_ips)
    col2.metric(t("high_risk"), high_count)
    col3.metric(t("medium_risk"), medium_count)
    col4.metric(t("low_risk"), low_count)
    col5.metric(t("failed_requests"), total_failed)


    st.subheader(t("risk_distribution"))

    risk_order = [
        t("risk_high_label"),
        t("risk_medium_label"),
        t("risk_low_label"),
    ]

    risk_chart_df = pd.DataFrame({
        t("col_risk_level"): risk_order,
        t("col_count"): [
            high_count,
            medium_count,
            low_count,
        ],
    })


    fig = px.bar(
        risk_chart_df,
        x=t("col_risk_level"),
        y=t("col_count"),
        category_orders={t("col_risk_level"): risk_order},
    )

    st.plotly_chart(fig, use_container_width=True)




#####
    top_df = df.copy()

    # AVOID 0 Division
    top_df["failure_rate"] = (
        top_df["failed_count"] / top_df["access_count"]
    ).replace([float("inf"), -float("inf")], 0).fillna(0)

    top_df["priority_score"] = (
        top_df["risk_score"] * 2
        + top_df["failure_rate"] * 5
    )

    display_top_df = top_df.head(10).reset_index(drop=True)

    top_display = display_top_df[[
        "ip",
        "event",
        "priority_score",
        "risk_score",
        "failure_rate",
        "access_count",
        "failed_count",
    ]].copy()

    top_display = top_display.rename(columns={
        "ip": t("col_ip"),
        "event": t("col_event"),
        "priority_score": t("col_priority_score"),
        "risk_score": t("col_risk_score"),
        "failure_rate": t("col_failure_rate"),
        "access_count": t("col_access_count"),
        "failed_count": t("col_failed_count"),
    })

    event_top = st.dataframe(
        top_display,
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
        ####



    st.markdown(f"## {t('time_series_analysis')}")

    if st.session_state.raw_logs:
        raw_df = pd.DataFrame(st.session_state.raw_logs)
        time_df = create_time_series(raw_df, interval="5min")
        #Plotyグラフ描画
        fig = create_timeline_chart(
            time_df,
            t("timeline_chart_title")
        )

        #st.plotly_chart(fig, use_container_width=True)
        st.plotly_chart(
            fig,
            use_container_width=True,
            key="overall_timeline_chart"
        )


        #####
        st.markdown(f"## 🚨 {t('detected_anomalies')}")

        anomaly_df = time_df[time_df["is_anomaly"]]

        if anomaly_df.empty:
            st.success(t("no_anomalies"))
        else:
            anomaly_display = anomaly_df[[
                "time_bucket",
                "ip",
                "access_count",
                "failed_count",
                "failure_rate",
                "anomaly_reason"
            ]].copy()

            anomaly_display = anomaly_display.rename(columns={
                "time_bucket": t("col_time"),
                "ip": t("col_ip"),
                "access_count": t("col_access_count"),
                "failed_count": t("col_failed_count"),
                "failure_rate": t("col_failure_rate"),
                "anomaly_reason": t("col_anomaly_reason"),
            })

            col_anomaly = t("col_anomaly_reason")

            anomaly_display[col_anomaly] = anomaly_display[col_anomaly].apply(translate_anomaly_reason)
            st.dataframe(
                anomaly_display,
                use_container_width=True,
                hide_index=True
            )

    else:
        st.info(t("no_time_series"))

   ########
    summary = generate_summary(df)

    st.markdown(f"## {t('security_summary')}")
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
        "signals_jp",
        "access_count",
        "recommended_action_jp",
    ]].copy()

    df_display = df_display.rename(columns={
        "ip": t("col_ip"),
        "event": t("col_event"),
        "risk_label": t("col_risk_level"),
        "risk_score": t("col_risk_score"),
        "signals_jp": t("signals"),
        "access_count": t("col_access_count"),
        "recommended_action_jp": t("recommended_action"),
    })

    st.markdown(f"## {t('filters')}")

    risk_filter = st.selectbox(
        t("filter_by_risk"),
        ["ALL", "HIGH", "MEDIUM", "LOW"]
    )

    risk_col = t("col_risk_level")
    if risk_filter != "ALL":
        df_view = df_display[df_display[risk_col] == risk_filter]
    else:
        df_view = df_display


    st.markdown(f"## {t('analysis_table')}")

    event = st.dataframe(
        df_view.style.map(highlight_risk, subset=[risk_col]),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )


    st.markdown(f"### {t('export')}")

    csv = df_view.to_csv(index=False).encode("utf-8")

    st.download_button(
        label=t("download_csv"),
        data=csv,
        file_name="security_analysis.csv",
        mime="text/csv"
    )


    selected_rows = event.selection.rows


    if selected_rows:
        selected_ip_from_table = df_view.iloc[selected_rows[0]][t("col_ip")]
    else:
        selected_ip_from_table = None

    if selected_ip_from_top:
        selected_ip = selected_ip_from_top
    elif selected_ip_from_table:
        selected_ip = selected_ip_from_table
    else:
        selected_ip = df.iloc[0]["ip"]

    selected = df[df["ip"] == selected_ip].iloc[0]

    st.markdown(f"## {t('high_risk_ips')}")

    high_risk_df = df[df["risk_label"] == "HIGH"]

    if high_risk_df.empty:
        st.success(t("no_high_risk_ips"))
    else:
        high_risk_display = high_risk_df[[
            "ip",
            "event",
            "risk_label",
            "risk_score",
            "access_count",
            "recommended_action_jp",
        ]].copy()

        high_risk_display = high_risk_display.rename(columns={
            "ip": t("col_ip"),
            "event": t("col_event"),
            "risk_label": t("col_risk_level"),
            "risk_score": t("col_risk_score"),
            "access_count": t("col_access_count"),
            "recommended_action_jp": t("recommended_action"),
        })

        st.dataframe(
            high_risk_display,
            use_container_width=True,
            hide_index=True
        )


### IP DETAIL
    render_ip_detail(selected, selected_ip)
    with st.expander(f"📈 {t('timeline_analysis')}"):
        render_selected_ip_timeline(selected_ip)
    with st.expander(f"🤖 {t('ai_explanation')}"):
        render_ai_explanation(selected, selected_ip)
