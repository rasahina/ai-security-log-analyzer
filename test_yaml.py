import yaml

with open("guides/response_guides.yaml", encoding="utf-8") as f:
    data = yaml.safe_load(f)

print(data)