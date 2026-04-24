import streamlit as st
import requests
import pandas as pd

st.title("AI Security Log Analyzer")

st.write("ログファイルをアップロードしてください")

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

        st.subheader("Analysis Result")
        st.dataframe(df)

        st.subheader("High Risk IPs")
        high_risk_df = df[df["risk_level"] == "HIGH"]
        st.dataframe(high_risk_df)