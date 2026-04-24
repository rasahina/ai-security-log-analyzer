import streamlit as st
import requests

st.title("AI Security Log Analyzer")

log_input = st.text_area("Paste your log here", height=200)

if st.button("Analyze"):
    response = requests.post(
        "http://127.0.0.1:8000/analyze",
        json={"log": log_input}
    )

    data = response.json()

    for item in data:
        level = item["risk_level"]

        if level == "HIGH":
            st.error(item)
        elif level == "MEDIUM":
            st.warning(item)
        else:
            st.success(item)