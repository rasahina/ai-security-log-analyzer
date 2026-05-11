ALLOWED_FIELDS = (
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


def _minimize_value(field: str, value):
    if field == "parser_warnings":
        return _normalize_parser_warnings(value)

    if isinstance(value, str):
        return value.strip()

    return value


def minimize_record(record: dict) -> dict:
    return {
        field: _minimize_value(field, record[field])
        for field in ALLOWED_FIELDS
        if field in record
    }
