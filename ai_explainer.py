import requests

OLLAMA_URL = "http://172.30.176.1:11434/api/generate"
MODEL = "qwen2.5:3b"


def explain_detection(detection_data: dict) -> str:
    event = detection_data.get("event")
    risk_level = detection_data.get("risk_level") or detection_data.get("risk_label")
    recommended_action = detection_data.get("recommended_action")

    prompt = f"""
You are a cybersecurity explanation assistant.

Your role:
- Explain the detection result based only on the provided data.
- Do not perform detection or risk evaluation.

Rules:
- Use only observable facts from the input.
- Do not infer attacker intent (e.g., malicious intent, exploitation).
- Avoid speculative words such as "potential", "possible".
- Avoid vague phrases such as "security concerns" or "under suspicion".

- Write 1-2 complete sentences in natural language.
- Combine multiple signals into a coherent explanation.
- Include key signals such as:
  - failure rate
  - access patterns
  - sensitive endpoints (e.g., /admin, /login)
  - detected patterns (e.g., brute force, scanning)

- Do not use bullet points.
- Do not output lists like ['...']; convert them into natural language.
- Do not include recommendations or conclusions in the Reason.
- Do not describe what should be done.
- Do not describe the actor (e.g., attacker, entity, user).
- Do not infer intent or purpose.
- Describe only observed patterns.

Style guidance:
- Prefer factual verbs such as "shows", "includes", "has".
- Keep the explanation concise but informative.
- Use "includes" instead of phrases like "suggests" or "indicating".
- Do not explain system logic (e.g., detection triggers).
- Describe only observed behavior.

- Do not use words like "possibly", "indicating", or "suggests".
- Do not describe causality or justification.
- Do not evaluate the activity (e.g., suspicious, concerning).
- Only describe observed patterns.

- Do not use phrases like "suspicious activity".
- Avoid repeating the same idea in different forms.

Evidence:
IP: {detection_data.get("ip")}
Risk score: {detection_data.get("risk_score")}
Access count: {detection_data.get("access_count")}
Failed count: {detection_data.get("failed_count")}
Suspicious paths: {detection_data.get("suspicious_paths")}
Reasons: {detection_data.get("reasons")}
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.2,
            },
            timeout=60,
        )
        response.raise_for_status()
        reason = response.json().get("response", "").strip()

    except requests.exceptions.RequestException:
        reason = "AI explanation unavailable."

    # 👇ここが重要：Pythonで整形
    return f"""Event:
{event}

Risk level:
{risk_level}

Reason:
{reason}

Recommended action:
{recommended_action}"""