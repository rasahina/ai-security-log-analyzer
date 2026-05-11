import yaml

from core.config import DATA_ENGINE_POLICY_PATH_V2


DEFAULT_POLICY = {
    "allowed_fields": [
        "timestamp",
        "ip",
        "method",
        "url",
        "status",
        "log_type",
        "level",
        "error_message",
        "user_agent",
        "line_number",
        "parse_status",
        "parser_warnings",
    ],
    "string_transforms": {
        "trim": True,
    },
    "field_limits": {},
}


def load_policy() -> dict:
    try:
        with open(DATA_ENGINE_POLICY_PATH_V2, "r", encoding="utf-8") as f:
            policy = yaml.safe_load(f) or {}
    except FileNotFoundError:
        policy = {}

    return {
        "allowed_fields": policy.get("allowed_fields", DEFAULT_POLICY["allowed_fields"]),
        "string_transforms": policy.get("string_transforms", DEFAULT_POLICY["string_transforms"]),
        "field_limits": policy.get("field_limits", DEFAULT_POLICY["field_limits"]),
    }


FALLBACK_ALLOWED_FIELDS = (
    "timestamp",
    "ip",
    "method",
    "url",
    "status",
    "log_type",
    "level",
    "error_message",
    "user_agent",
    "line_number",
    "parse_status",
    "parser_warnings",
)


def _normalize_parser_warnings(value) -> list[str]:
    if not isinstance(value, list):
        return []

    return [warning.strip() for warning in value if isinstance(warning, str)]


def _minimize_value(field: str, value, policy: dict):
    if field == "parser_warnings":
        return _normalize_parser_warnings(value)

    if isinstance(value, str):
        if policy.get("string_transforms", {}).get("trim", False):
            value = value.strip()

        limit = policy.get("field_limits", {}).get(field)
        if isinstance(limit, int) and limit >= 0:
            value = value[:limit]

    return value


def minimize_record(record: dict) -> dict:
    policy = load_policy()
    allowed_fields = policy.get("allowed_fields") or FALLBACK_ALLOWED_FIELDS

    return {
        field: _minimize_value(field, record[field], policy)
        for field in allowed_fields
        if field in record
    }
