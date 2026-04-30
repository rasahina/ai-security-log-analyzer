import re
import os
import json
from datetime import datetime
from urllib.parse import unquote


GUARD_LOG_FILE = "logs/ai_guard.log"

MAX_TEXT_LENGTH = 200
MAX_LIST_ITEMS = 10

ALLOWED_KEYS = {
    "ip",
    "event",
    "risk_level",
    "risk_score",
    "access_count",
    "failed_count",
    "suspicious_paths",
    "signals",
    "recommended_action",
}

DANGEROUS_PATTERNS = [
    r"ignore.*previous",
    r"forget.*instructions",
    r"system.*prompt",
    r"developer.*message",
    r"you.*are.*chatgpt",
    r"follow.*instructions",
    r"execute.*code",
    r"reveal.*prompt",
    r"print.*prompt",
    r"\bexecute\b",
]

def normalize_for_detection(text: str) -> str:
    text = unquote(text)  # %20 などを復元
    text = text.lower()
    text = re.sub(r"[_\-./?=&%]+", " ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def write_guard_logs(guard_logs):
    if not guard_logs:
        return

    os.makedirs("logs", exist_ok=True)

    existing = set()

    # ① 既存ログ読み込み（ここ追加）
    if os.path.exists(GUARD_LOG_FILE):
        with open(GUARD_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                existing.add(line.strip())

    # ② 書き込み（ここ変更）
    with open(GUARD_LOG_FILE, "a", encoding="utf-8") as f:
        for item in guard_logs:
            line = json.dumps(item, ensure_ascii=False)

            if line not in existing:
                f.write(line + "\n")


def make_guard_log(field: str, reason: str, action: str, sample: str) -> dict:
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "field": field,
        "reason": reason,
        "action": action,
        "sample": str(sample)[:80],
    }


def strip_dangerous_phrases(text: str, field: str, guard_logs: list) -> str:
    normalized = normalize_for_detection(text)
    compact = normalized.replace(" ", "")

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, normalized) or re.search(pattern, compact):
            guard_logs.append(
                make_guard_log(
                    field=field,
                    reason=f"dangerous_phrase_detected:{pattern}",
                    action="blocked",
                    sample=text,
                )
            )
            return ""

    return text


def clean_text(value, field="unknown", max_length=MAX_TEXT_LENGTH, guard_logs=None):
    if guard_logs is None:
        guard_logs = []

    if value is None:
        return ""

    original = str(value)
    text = original.replace("\n", " ").replace("\r", " ")
    text = re.sub(r"[<>`{}]", "", text)
    text = re.sub(r"\s+", " ", text).strip()

    if text != original:
        guard_logs.append(
            make_guard_log(
                field=field,
                reason="unsafe_characters_removed",
                action="sanitized",
                sample=original,
            )
        )

    text = strip_dangerous_phrases(text, field, guard_logs)

    if len(text) > max_length:
        guard_logs.append(
            make_guard_log(
                field=field,
                reason="text_truncated",
                action="truncated",
                sample=text,
            )
        )
        text = text[:max_length]

    return text


def clean_list(values, field="unknown", max_items=MAX_LIST_ITEMS, guard_logs=None):
    if guard_logs is None:
        guard_logs = []

    if not isinstance(values, list):
        guard_logs.append(
            make_guard_log(
                field=field,
                reason="invalid_list_type",
                action="replaced_with_empty_list",
                sample=values,
            )
        )
        return []

    cleaned = []

    if len(values) > max_items:
        guard_logs.append(
            make_guard_log(
                field=field,
                reason="list_truncated",
                action="truncated",
                sample=f"{len(values)} items",
            )
        )

    for item in values[:max_items]:
        cleaned_item = clean_text(
            item,
            field=field,
            guard_logs=guard_logs
        )
        if cleaned_item:
            cleaned.append(cleaned_item)

    return cleaned


def enforce_schema(payload: dict) -> dict:
    return {key: payload.get(key) for key in ALLOWED_KEYS}


def build_safe_ai_payload(selected: dict) -> tuple[dict, list]:
    guard_logs = []

    payload = {
        "ip": clean_text(selected.get("ip"), "ip", 50, guard_logs),
        "event": clean_text(selected.get("event"), "event", 120, guard_logs),
        "risk_level": clean_text(selected.get("risk_label"), "risk_level", 20, guard_logs),
        "risk_score": int(selected.get("risk_score", 0)),
        "access_count": int(selected.get("access_count", 0)),
        "failed_count": int(selected.get("failed_count", 0)),
        "suspicious_paths": clean_list(
            selected.get("suspicious_paths"),
            field="suspicious_paths",
            max_items=5,
            guard_logs=guard_logs,
        ),
        "signals": clean_list(
            selected.get("reasons"),
            field="signals",
            max_items=5,
            guard_logs=guard_logs,
        ),
        "recommended_action": clean_text(
            selected.get("recommended_action"),
            "recommended_action",
            200,
            guard_logs,
        ),
    }

    return enforce_schema(payload), guard_logs