import json

from core.config import DEBUG_DIR

DEBUG = True


def debug_print(*args):
    if DEBUG:
        print("DEBUG:", *args)


def debug_dump_json(filename, data):
    if not DEBUG:
        return

    DEBUG_DIR.mkdir(parents=True, exist_ok=True)

    output_path = DEBUG_DIR / filename

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)