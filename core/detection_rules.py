import yaml

from core.config import (
    DETECTION_RULES_PATH,
    DETECTION_RULES_PATH_V2,
)

RULE_PATHS = {
    "classic": DETECTION_RULES_PATH,
    "v2": DETECTION_RULES_PATH_V2,
}

def load_detection_rules(rule_type="classic"):

    path = RULE_PATHS.get(rule_type)

    if path is None:
        raise ValueError(f"Unknown rule_type: {rule_type}")

    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f) or {}

    return rules