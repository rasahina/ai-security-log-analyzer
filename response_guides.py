import yaml

GUIDE_FILE = "guides/response_guides.yaml"

def load_guides():
    with open(GUIDE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

GUIDES = load_guides()

def normalize_attack_type(attack_type: str) -> str:
    return attack_type.replace(" ", "_")

def get_guides(attack_type: str):
    if not attack_type:
        return []

    result = []

    for t in attack_type.split(", "):
        key = normalize_attack_type(t)
        guide = GUIDES.get(key)

        if guide:
            result.append(guide)

    return result