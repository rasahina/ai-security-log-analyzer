from parsers.log_parser import parse_log_lines
from correlation import correlate_logs

with open("data/test_mixed.log") as f:
    lines = f.readlines()

parsed = parse_log_lines(lines)
correlated = correlate_logs(parsed)

print(correlated)