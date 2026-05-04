import yaml
from core.config import DETECTION_RULES_PATH
from core.debug import debug_print

def load_detection_rules():
    debug_print("LOADED FILE:", DETECTION_RULES_PATH)

    with open(DETECTION_RULES_PATH, "r") as f:
        rules = yaml.safe_load(f)

    debug_print("SIGNALS:", rules.get("signals", {}).keys())

    return rules