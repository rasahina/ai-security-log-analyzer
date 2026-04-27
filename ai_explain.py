import requests

OLLAMA_URL = "http://172.30.176.1:11434/api/generate"
MODEL = "qwen2.5:3b"


def explain_log(log: str) -> str:
    prompt = f"""
You are a cybersecurity log analysis assistant.

Analyze the log strictly based on evidence.
Do not overestimate or underestimate risk.

Guidelines:
- Access to sensitive endpoints such as /admin increases risk
- Failed authentication with 401 indicates suspicious access, but not a confirmed attack
- Single events should not be marked as High risk
- Do not assume the requester is a user, bot, or attacker unless the log proves it

Keep the answer concise.
Use one sentence for each field.
Do not use bullet points.

Return the answer in this format:

Event:
Risk level:
Reason:
Recommended action:

Log:
{log}
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=60,
    )

    response.raise_for_status()
    return response.json()["response"]


if __name__ == "__main__":
    log_entry = "suspicious access: 10.0.0.5 url=/admin status=401"
    result = explain_log(log_entry)
    print(result)