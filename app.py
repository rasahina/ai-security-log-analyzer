import streamlit as st
import requests
import pandas as pd

st.set_page_config(
    page_title="AI Security Log Analyzer",
    layout="wide"
)

st.title("AI Security Log Analyzer")
st.write("ログファイルをアップロードして、不審なアクセスを分析します。")

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

        data = response.json()
        df = pd.DataFrame(data)

        df = df.sort_values(by="risk_score", ascending=False)

        st.subheader("Summary")

        total_ips = len(df)
        high_count = len(df[df["risk_level"] == "HIGH"])
        medium_count = len(df[df["risk_level"] == "MEDIUM"])
        low_count = len(df[df["risk_level"] == "LOW"])
        total_access = df["access_count"].sum()
        total_failed = df["failed_count"].sum()

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric("Total IPs", total_ips)
        col2.metric("High Risk", high_count)
        col3.metric("Medium Risk", medium_count)
        col4.metric("Low Risk", low_count)
        col5.metric("Failed Requests", total_failed)

        st.subheader("Risk Distribution")
        risk_counts = df["risk_level"].value_counts()
        st.bar_chart(risk_counts)

        st.subheader("Analysis Result")
        st.dataframe(df, use_container_width=True)

        st.subheader("High Risk IPs")
        high_risk_df = df[df["risk_level"] == "HIGH"]
        st.dataframe(high_risk_df, use_container_width=True)

        st.subheader("IP Detail")

        selected_ip = st.selectbox("Select IP", df["ip"])

        selected = df[df["ip"] == selected_ip].iloc[0]

        st.write("Risk Level:", selected["risk_level"])
        st.write("Risk Score:", selected["risk_score"])
        st.write("Access Count:", selected["access_count"])
        st.write("Failed Count:", selected["failed_count"])
        st.write("Suspicious Paths:", selected["suspicious_paths"])
        st.write("Status Counts:", selected["status_counts"])
        st.write("Reasons:", selected["reasons"])