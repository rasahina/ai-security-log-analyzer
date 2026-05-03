from data_layer.log_parser import parse_log_lines
from data_layer.database import (
    save_analysis_run,
    save_raw_logs,
    create_analysis_file,
)


def create_run_from_text(text: str, source: str):
    lines = text.splitlines()
    parsed_logs, skipped_logs = parse_log_lines(lines)

    run_id = save_analysis_run([], source=source)
    save_raw_logs(run_id, parsed_logs)

    return run_id, parsed_logs, skipped_logs


def create_run_from_files(files: list[dict]):
    run_id = save_analysis_run([], source="multi-upload")

    all_raw_logs = []
    all_skipped_logs = []

    for f in files:
        file_name = f["file_name"]
        text = f["text"]

        lines = text.splitlines()
        parsed_logs, skipped_logs = parse_log_lines(lines)

        file_id = create_analysis_file(run_id, file_name)
        save_raw_logs(run_id, parsed_logs, file_id=file_id)

        all_raw_logs.extend(parsed_logs)
        all_skipped_logs.extend(skipped_logs)

    return run_id, all_raw_logs, all_skipped_logs


def build_log_stats(parsed_logs, skipped_logs):
    parsed_count = len(parsed_logs)
    skipped_count = len(skipped_logs)

    return {
        "total": parsed_count + skipped_count,
        "parsed": parsed_count,
        "skipped": skipped_count,
    }