import json
import os
from analyzer import analyze_log_file

INPUT_FILE = "data/sample.log"
OUTPUT_FILE = "output/result.json"


def main():
    results = analyze_log_file(INPUT_FILE)

    os.makedirs("output", exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"Saved analysis to {OUTPUT_FILE}")

    print("\n--- Final Analysis ---")
    for item in results:
        print(f"\nIP: {item['ip']}")
        print(f"  Risk Level       : {item['risk_level']}")
        print(f"  Risk Score       : {item['risk_score']}")
        print(f"  Access Count     : {item['access_count']}")
        print(f"  Failed Count     : {item['failed_count']}")
        print(f"  Suspicious Paths : {item['suspicious_paths']}")
        print(f"  Status Counts    : {item['status_counts']}")
        print(f"  Reasons          : {item['reasons']}")


if __name__ == "__main__":
    main()