import yaml
from pathlib import Path


def load_rules(rules_dir):
    rules_path = Path(rules_dir)
    rules = []

    for rule_file in rules_path.glob("*.yaml"):
        with open(rule_file, "r") as file:
            rule = yaml.safe_load(file)
            rule["file"] = str(rule_file)
            rules.append(rule)

    return rules
