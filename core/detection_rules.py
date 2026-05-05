import yaml
from core.config import DETECTION_RULES_PATH

def load_detection_rules():

    with open(DETECTION_RULES_PATH, "r") as f:
        rules = yaml.safe_load(f)

    return rules