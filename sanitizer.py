def sanitize_reason(text: str) -> str:
    if not text:
        return ""

    forbidden = [
        "attacker",
        "malicious",
        "potential",
        "suggests",
        "indicating",
        "unauthorized entity",
        "unauthorized activities",
        "attempted",
    ]

    for word in forbidden:
        text = text.replace(word, "")
        text = text.replace(word.capitalize(), "")

    text = " ".join(text.split())
    return text.strip()


def normalize_reason(text: str) -> str:
    if not text:
        return ""

    if not text.endswith("."):
        text += "."

    return text


def is_valid_reason(text: str) -> bool:
    if not text:
        return False

    if len(text) < 20:
        return False

    return True


def fallback_reason(data: dict) -> str:
    return (
        f"IP {data['ip']} では、ログイン関連エンドポイントへの繰り返しの失敗アクセスが確認されています。"
    )