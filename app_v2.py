import os

import pandas as pd
import requests
import streamlit as st


API_URL = os.getenv("API_V2_URL", "http://localhost:8000/analyze-v2")


def post_analyze_v2(log_text: str) -> dict:
    response = requests.post(API_URL, json={"log": log_text}, timeout=30)
    response.raise_for_status()
    return response.json()


def format_time_range(value):
    if not value:
        return ""

    start = value.get("start", "")
    end = value.get("end", "")

    if start and end:
        return f"{start} - {end}"

    return start or end


def render_overview(report: dict) -> None:
    st.header("Overview")
    col1, col2 = st.columns(2)
    col1.metric("Schema version", report.get("schema_version", ""))
    col2.metric("Generated at", report.get("generated_at", ""))


def render_ip_reports(report: dict) -> None:
    st.header("IP Reports")

    rows = []
    for ip_report in report.get("ip_reports", []):
        rows.append({
            "source_ip": ip_report.get("source_ip", ""),
            "overall_score": ip_report.get("overall_score", ""),
            "risk_level": ip_report.get("risk_level", ""),
            "attack_count": ip_report.get("attack_count", ""),
            "time_range": format_time_range(ip_report.get("time_range")),
        })

    if not rows:
        st.info("No IP reports in DetectionReport.")
        return

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_findings(report: dict) -> None:
    st.header("Findings")

    rows = []
    for ip_report in report.get("ip_reports", []):
        for finding in ip_report.get("findings", []):
            rows.append({
                "finding_id": finding.get("finding_id", ""),
                "finding_type": finding.get("finding_type", ""),
                "attack_type": finding.get("attack_type", ""),
                "source_ip": finding.get("source_ip", ""),
                "score": finding.get("score", ""),
                "time_range": format_time_range(finding.get("time_range")),
            })

    if not rows:
        st.info("No findings in DetectionReport.")
        return

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


st.set_page_config(page_title="DetectionReport Viewer", layout="wide")

st.title("DetectionReport Viewer")

if "detection_report_v2" not in st.session_state:
    st.session_state.detection_report_v2 = None

uploaded_file = st.file_uploader("Upload log file", type=["log", "txt"])
log_text = st.text_area("Or paste log text", height=220)

if st.button("Analyze", type="primary"):
    selected_text = log_text

    if uploaded_file is not None:
        selected_text = uploaded_file.getvalue().decode("utf-8", errors="replace")

    if not selected_text.strip():
        st.error("Upload a log file or paste log text before analyzing.")
    else:
        try:
            st.session_state.detection_report_v2 = post_analyze_v2(selected_text)
        except requests.HTTPError as exc:
            detail = exc.response.text if exc.response is not None else str(exc)
            st.error(f"Analyze request failed: {detail}")
        except requests.RequestException as exc:
            st.error(f"Could not connect to API: {exc}")

report = st.session_state.detection_report_v2

if report:
    render_overview(report)
    render_ip_reports(report)
    render_findings(report)

    with st.expander("DetectionReport JSON"):
        st.json(report)
