from data_layer.analysis_repository import create_run_from_text
from data_layer.database import get_ip_events
from core.v2_pipeline import run_v2_pipeline


def main():
    log_path = "data/test_mixed.log"

    with open(log_path, "r", encoding="utf-8") as f:
        text = f.read()

    run_id, parsed_logs, skipped_logs = create_run_from_text(
        text=text,
        source="v2-test",
    )

    print(f"run_id: {run_id}")
    print(f"parsed_logs: {len(parsed_logs)}")
    print(f"skipped_logs: {len(skipped_logs)}")

    events_by_ip = get_ip_events(run_id)

    result = run_v2_pipeline(events_by_ip)

    print("V2 pipeline completed.")
    print(f"IPs analyzed: {len(events_by_ip)}")
    print(f"Risk entries: {len(result['ip_reports'])}")


if __name__ == "__main__":
    main()