from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
DEBUG_DIR = PROJECT_ROOT / "debug"
OUTPUT_DIR = PROJECT_ROOT / "output"


DETECTION_RULES_PATH_V2 = (
    CONFIG_DIR / "v2_detection_rules.yaml"
)
DETECTION_RULES_PATH_V2_SIGNALS = (
    CONFIG_DIR / "v2_signals.yaml"
)
DETECTION_RULES_PATH_V2_CLUSTERS = (
    CONFIG_DIR / "v2_clusters.yaml"
)
DETECTION_RULES_PATH_V2_ATTACKS = (
    CONFIG_DIR / "v2_attacks.yaml"
)
DETECTION_RULES_PATH_V2_EVALUATION = (
    CONFIG_DIR / "v2_evaluation_rules.yaml"
)
DATA_ENGINE_POLICY_PATH_V2 = (
    CONFIG_DIR / "v2_data_engine_policy.yaml"
)
DB_PATH = DATA_DIR / "security_analyzer.db"
