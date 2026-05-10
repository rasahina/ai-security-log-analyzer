import yaml

from core.config import (
    DETECTION_RULES_PATH_V2,
    DETECTION_RULES_PATH_V2_SIGNALS,
)

RULE_PATHS = {
    "v2": DETECTION_RULES_PATH_V2,
    "signals": DETECTION_RULES_PATH_V2_SIGNALS,
}

def load_detection_rules(rule_type="v2"):

    path = RULE_PATHS.get(rule_type)

    if path is None:
        raise ValueError(f"Unknown rule_type: {rule_type}")

    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f) or {}

    return rules