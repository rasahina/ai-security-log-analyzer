import requests
from sanitizer import (
    sanitize_reason,
    normalize_reason,
    is_valid_reason,
    fallback_reason
)
import os

AI_MODE = os.getenv("AI_MODE", "off")
OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://172.30.176.1:11434/api/generate"
)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")


def load_prompt():
    with open("prompts/detection_prompt.txt", "r", encoding="utf-8") as f:
        return f.read()

def explain_detection(detection_data: dict, ai_enabled: bool) -> str:
    event = detection_data.get("event")
    risk_level = detection_data.get("risk_level") or detection_data.get("risk_label")
    recommended_action = detection_data.get("recommended_action")

    #Format 
    ip = detection_data.get("ip", "")
    suspicious_paths = ", ".join(detection_data.get("suspicious_paths", []))
    signals = ", ".join(detection_data.get("signals", []))
    
    #NO AI MODE
    if not ai_enabled :
        return f"""Event:
    {event}


    Risk level:
    {risk_level}

    Reason:
    AI explanation is disabled.

    Recommended action:
    {recommended_action}"""
    #-----------------------------

    prompt_template = load_prompt()

    prompt = prompt_template.format(
        ip = ip,
        risk_score=detection_data.get("risk_score"),
        access_count=detection_data.get("access_count"),
        failed_count=detection_data.get("failed_count"),
        suspicious_paths=suspicious_paths,
        signals= signals,
    )

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.2,
            },
            timeout=10,
        )
        response.raise_for_status()
        reason = response.json().get("response", "").strip()
        

        reason = sanitize_reason(reason)
        reason = normalize_reason(reason)

        if not is_valid_reason(reason):
            reason = fallback_reason(detection_data)

    except requests.exceptions.RequestException:
        reason = "AI explanation unavailable."

    # 👇ここが重要：Pythonで整形
    return reason