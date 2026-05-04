from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
GUIDES_DIR = PROJECT_ROOT / "guides"

DETECTION_RULES_PATH = CONFIG_DIR / "timeseries_detection_rules.yaml"
DB_PATH = DATA_DIR / "security_analyzer.db"