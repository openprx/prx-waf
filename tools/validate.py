#!/usr/bin/env python3
"""
validate.py - Validate prx-waf YAML rule files

Checks:
- Required fields present
- Valid severity / action / paranoia values
- No duplicate IDs
- Regex patterns compilable
- Prints summary report

Usage:
    python validate.py rules/
    python validate.py rules/owasp-crs/sqli.yaml

Apache License 2.0
"""

import re
import sys
import argparse
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"id", "name", "severity", "field", "operator", "value", "action"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_ACTIONS = {"block", "log", "pass"}
VALID_FIELDS = {
    "path", "query", "body", "headers", "cookies", "all",
    "method", "content_type", "content_length",
    "path_length", "query_arg_count", "user_agent",
}
VALID_OPERATORS = {
    "regex", "contains", "not_in", "gt", "lt", "detect_sqli",
    "detect_xss", "pm_from_file", "pm",
}
VALID_PARANOIA = {1, 2, 3, 4}


# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

class ValidationError:
    def __init__(self, file: str, rule_id: str, message: str, level: str = "ERROR"):
        self.file = file
        self.rule_id = rule_id
        self.message = message
        self.level = level

    def __str__(self):
        return f"[{self.level}] {self.file} / {self.rule_id}: {self.message}"


def validate_rule(rule: dict, file_path: str, seen_ids: dict) -> list[ValidationError]:
    errors = []
    rule_id = str(rule.get("id", "<unknown>"))

    # Required fields
    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(ValidationError(file_path, rule_id, f"Missing required fields: {missing}"))

    # Duplicate IDs
    if rule_id in seen_ids:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Duplicate ID (also in {seen_ids[rule_id]})"
        ))
    else:
        seen_ids[rule_id] = file_path

    # Severity
    severity = rule.get("severity", "")
    if severity not in VALID_SEVERITIES:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Invalid severity '{severity}'. Must be one of: {VALID_SEVERITIES}",
            level="ERROR"
        ))

    # Action
    action = rule.get("action", "")
    if action not in VALID_ACTIONS:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Invalid action '{action}'. Must be one of: {VALID_ACTIONS}",
            level="ERROR"
        ))

    # Field
    field = rule.get("field", "")
    if field not in VALID_FIELDS:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Invalid field '{field}'. Must be one of: {VALID_FIELDS}",
            level="WARN"
        ))

    # Operator
    operator = rule.get("operator", "")
    if operator not in VALID_OPERATORS:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Invalid operator '{operator}'. Must be one of: {VALID_OPERATORS}",
            level="WARN"
        ))

    # Paranoia level
    paranoia = rule.get("paranoia")
    if paranoia is not None and paranoia not in VALID_PARANOIA:
        errors.append(ValidationError(
            file_path, rule_id,
            f"Invalid paranoia level '{paranoia}'. Must be 1-4",
            level="WARN"
        ))

    # Regex compilation
    if operator == "regex":
        pattern = rule.get("value", "")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(ValidationError(
                    file_path, rule_id,
                    f"Invalid regex pattern: {e}",
                    level="WARN"
                ))

    # Tags must be a list if present
    tags = rule.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append(ValidationError(
            file_path, rule_id,
            f"'tags' must be a list, got {type(tags).__name__}",
            level="ERROR"
        ))

    return errors


def validate_file(yaml_path: Path, seen_ids: dict) -> tuple[int, list[ValidationError]]:
    """Validate a single YAML file. Returns (rule_count, errors)."""
    errors = []
    try:
        with open(yaml_path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        errors.append(ValidationError(str(yaml_path), "<file>", f"YAML parse error: {e}"))
        return 0, errors

    if doc is None:
        return 0, errors

    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        errors.append(ValidationError(str(yaml_path), "<file>", "'rules' must be a list"))
        return 0, errors

    for rule in rules:
        if not isinstance(rule, dict):
            errors.append(ValidationError(str(yaml_path), "<unknown>", "Rule entry is not a dict"))
            continue
        rule_errors = validate_rule(rule, str(yaml_path), seen_ids)
        errors.extend(rule_errors)

    return len(rules), errors


def collect_yaml_files(path: Path) -> list[Path]:
    """Collect all .yaml files under path (recursive)."""
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.yaml"))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def run_validation(target: Path, quiet: bool = False) -> int:
    """Run full validation. Returns exit code (0=pass, 1=errors found)."""
    yaml_files = collect_yaml_files(target)
    if not yaml_files:
        print(f"No YAML files found under {target}")
        return 1

    seen_ids: dict[str, str] = {}
    all_errors: list[ValidationError] = []
    total_rules = 0
    per_category: dict[str, int] = {}
    file_count = 0

    for yaml_path in yaml_files:
        count, errors = validate_file(yaml_path, seen_ids)
        total_rules += count
        file_count += 1

        # Track per-category counts
        category = yaml_path.parent.name
        per_category[category] = per_category.get(category, 0) + count

        if errors:
            all_errors.extend(errors)

    # Print report
    print("=" * 60)
    print("prx-waf Rule Validation Report")
    print("=" * 60)
    print(f"Files validated: {file_count}")
    print(f"Total rules:     {total_rules}")
    print()
    print("Rules by category:")
    for cat, cnt in sorted(per_category.items()):
        print(f"  {cat:<30} {cnt:>5} rules")
    print()

    errors_only = [e for e in all_errors if e.level == "ERROR"]
    warnings_only = [e for e in all_errors if e.level == "WARN"]

    if errors_only:
        print(f"ERRORS ({len(errors_only)}):")
        for e in errors_only:
            print(f"  {e}")
        print()

    if warnings_only and not quiet:
        print(f"WARNINGS ({len(warnings_only)}):")
        for w in warnings_only[:20]:  # limit to 20 warnings
            print(f"  {w}")
        if len(warnings_only) > 20:
            print(f"  ... and {len(warnings_only) - 20} more warnings")
        print()

    if errors_only:
        print(f"RESULT: FAILED ({len(errors_only)} errors, {len(warnings_only)} warnings)")
        return 1
    else:
        print(f"RESULT: PASSED (0 errors, {len(warnings_only)} warnings)")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate prx-waf YAML rule files"
    )
    parser.add_argument("target", help="YAML file or directory to validate")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress warnings, show errors only"
    )
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)

    exit_code = run_validation(target, quiet=args.quiet)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
