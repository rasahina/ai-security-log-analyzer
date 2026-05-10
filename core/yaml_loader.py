import yaml

from core.config import (
    DETECTION_RULES_PATH_V2_SIGNALS,
    DETECTION_RULES_PATH_V2_CLUSTERS,
    DETECTION_RULES_PATH_V2_ATTACKS,
    DETECTION_RULES_PATH_V2_EVALUATION,
)


YAML_CONFIG_PATHS = {
    "signals": DETECTION_RULES_PATH_V2_SIGNALS,
    "clusters": DETECTION_RULES_PATH_V2_CLUSTERS,
    "attacks": DETECTION_RULES_PATH_V2_ATTACKS,
    "evaluation": DETECTION_RULES_PATH_V2_EVALUATION,
}


def load_yaml_config(config_type: str) -> dict:
    path = YAML_CONFIG_PATHS.get(config_type)

    if path is None:
        raise ValueError(f"Unknown config_type: {config_type}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    return config