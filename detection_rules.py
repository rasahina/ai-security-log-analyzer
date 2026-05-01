import yaml

def load_detection_rules():
    with open("config/detection_rules.yaml", "r") as f:
        return yaml.safe_load(f)