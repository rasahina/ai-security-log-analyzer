from parsers.log_parser import parse_log_lines

with open("data/test_mixed.log") as f:
    lines = f.readlines()

parsed = parse_log_lines(lines)

print(len(parsed))
print(parsed[:3])

