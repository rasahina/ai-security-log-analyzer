from pathlib import Path
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUIDES_DIR = PROJECT_ROOT / "guides"
INDEX_PATH = GUIDES_DIR / "index.yaml"

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_index():
    print("INDEX_PATH:", INDEX_PATH)
    print("INDEX_EXISTS:", INDEX_PATH.exists())
    return load_yaml(INDEX_PATH)

def get_attack_type_priority():
    index = load_index()
    return list(index.keys())


def is_known_attack_type(attack_type: str) -> bool:
    return attack_type in load_index()


def get_guide(attack_type):
    index = load_index()


    guide_path = index.get(attack_type)
    print("DEBUG attack_type:", attack_type)


    if not guide_path:
        print(f"[WARN] No guide found for: {attack_type}")
        guide_path = index.get("Suspicious Activity")

    if not guide_path:
        return None
    
    full_path = GUIDES_DIR / guide_path

    if not full_path.exists():
        print(f"[WARN] Guide file not found: {full_path}")
        return None


    return load_yaml(full_path)

def get_guides(attack_type):
    guides = []

    for attack in attack_type.split(", "):
        guide = get_guide(attack)

        if not guide:
            print(f"[WARN] Guide returned None for: {attack}")

        if guide:
            guides.append({
                "attack_type": attack,
                "guide": guide
            })

    return guides

def get_attack_type_priority():
    index = load_index()
    return list(index.keys())


def is_known_attack_type(attack_type: str) -> bool:
    return attack_type in load_index()