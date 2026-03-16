#!/usr/bin/env python3
"""
modsec2yaml.py - ModSecurity SecRule → prx-waf YAML converter

Parses ModSecurity .conf rule files and outputs prx-waf YAML format.

Usage:
    python modsec2yaml.py /path/to/crs/rules/ /path/to/output/
    python modsec2yaml.py --file /path/to/rule.conf /path/to/output/

Apache License 2.0
"""

import re
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Constants / mappings
# ---------------------------------------------------------------------------

# CRS file → target YAML file name mapping
CONF_TO_YAML = {
    "REQUEST-913-SCANNER-DETECTION.conf": "scanner-detection.yaml",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf": "protocol-enforcement.yaml",
    "REQUEST-921-PROTOCOL-ATTACK.conf": "protocol-attack.yaml",
    "REQUEST-922-MULTIPART-ATTACK.conf": "multipart-attack.yaml",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf": "lfi.yaml",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf": "rfi.yaml",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf": "rce.yaml",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf": "php-injection.yaml",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf": "generic-attack.yaml",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf": "xss.yaml",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "sqli.yaml",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf": "session-fixation.yaml",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf": "java-injection.yaml",
    # Response rules
    "RESPONSE-950-DATA-LEAKAGES.conf": "response-data-leakage.yaml",
    "RESPONSE-951-DATA-LEAKAGES-SQL.conf": "response-sql-errors.yaml",
    "RESPONSE-952-DATA-LEAKAGES-JAVA.conf": "response-java-errors.yaml",
    "RESPONSE-953-DATA-LEAKAGES-PHP.conf": "response-php-errors.yaml",
    "RESPONSE-954-DATA-LEAKAGES-IIS.conf": "response-iis-errors.yaml",
    "RESPONSE-955-WEB-SHELLS.conf": "response-web-shells.yaml",
    "RESPONSE-956-DATA-LEAKAGES-RUBY.conf": "response-ruby-errors.yaml",
    # Protocol / method enforcement
    "REQUEST-911-METHOD-ENFORCEMENT.conf": "method-enforcement.yaml",
}

# CRS file → category mapping
CONF_TO_CATEGORY = {
    "REQUEST-913-SCANNER-DETECTION.conf": "scanner",
    "REQUEST-920-PROTOCOL-ENFORCEMENT.conf": "protocol",
    "REQUEST-921-PROTOCOL-ATTACK.conf": "protocol",
    "REQUEST-922-MULTIPART-ATTACK.conf": "protocol",
    "REQUEST-930-APPLICATION-ATTACK-LFI.conf": "lfi",
    "REQUEST-931-APPLICATION-ATTACK-RFI.conf": "rfi",
    "REQUEST-932-APPLICATION-ATTACK-RCE.conf": "rce",
    "REQUEST-933-APPLICATION-ATTACK-PHP.conf": "php",
    "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf": "generic",
    "REQUEST-941-APPLICATION-ATTACK-XSS.conf": "xss",
    "REQUEST-942-APPLICATION-ATTACK-SQLI.conf": "sqli",
    "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf": "session",
    "REQUEST-944-APPLICATION-ATTACK-JAVA.conf": "java",
    "RESPONSE-950-DATA-LEAKAGES.conf": "data-leakage",
    "RESPONSE-951-DATA-LEAKAGES-SQL.conf": "data-leakage",
    "RESPONSE-952-DATA-LEAKAGES-JAVA.conf": "data-leakage",
    "RESPONSE-953-DATA-LEAKAGES-PHP.conf": "data-leakage",
    "RESPONSE-954-DATA-LEAKAGES-IIS.conf": "data-leakage",
    "RESPONSE-955-WEB-SHELLS.conf": "web-shell",
    "RESPONSE-956-DATA-LEAKAGES-RUBY.conf": "data-leakage",
    "REQUEST-911-METHOD-ENFORCEMENT.conf": "protocol",
}

# Variable → prx-waf field
VARIABLE_MAP = {
    "REQUEST_URI": "path",
    "REQUEST_URI_RAW": "path",
    "REQUEST_LINE": "path",
    "REQUEST_BASENAME": "path",
    "REQUEST_FILENAME": "path",
    "ARGS": "query",
    "ARGS_NAMES": "query",
    "ARGS_GET": "query",
    "ARGS_GET_NAMES": "query",
    "ARGS_POST": "body",
    "ARGS_POST_NAMES": "body",
    "REQUEST_BODY": "body",
    "REQUEST_BODY_LENGTH": "content_length",
    "REQUEST_HEADERS": "headers",
    "REQUEST_HEADERS:User-Agent": "user_agent",
    "REQUEST_HEADERS:Referer": "headers",
    "REQUEST_HEADERS:Content-Type": "content_type",
    "REQUEST_COOKIES": "cookies",
    "REQUEST_COOKIES_NAMES": "cookies",
    "REQUEST_METHOD": "method",
    "REQUEST_CONTENT_TYPE": "content_type",
    "FILES": "body",
    "XML": "body",
    "RESPONSE_BODY": "body",
    "RESPONSE_HEADERS": "headers",
    "RESPONSE_STATUS": "headers",
}

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "WARNING": "medium",
    "NOTICE": "low",
    # lowercase variants
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "notice": "low",
}

# IDs of paranoia gate rules / control rules to skip
SKIP_PATTERNS = [
    r"skipAfter:",
    r"TX:DETECTION_PARANOIA_LEVEL",
    r"TX:EXECUTING_PARANOIA_LEVEL",
    r"SecMarker",
    r"setvar:'tx\.anomaly_score",
    r"^#",
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def join_continuation_lines(text: str) -> list[str]:
    """Join backslash-continued lines into single logical lines."""
    lines = text.splitlines()
    joined = []
    buf = ""
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1]
        else:
            buf += stripped
            joined.append(buf)
            buf = ""
    if buf:
        joined.append(buf)
    return joined


def parse_actions_str(actions_str: str) -> dict:
    """Parse the action string from a SecRule (comma-separated key:value pairs)."""
    result: dict = {}
    tags: list[str] = []

    # We need to split on commas but not those inside single-quoted strings
    # Simple approach: iterate character by character
    parts = []
    current = ""
    in_quote = False
    for ch in actions_str:
        if ch == "'" and not in_quote:
            in_quote = True
            current += ch
        elif ch == "'" and in_quote:
            in_quote = False
            current += ch
        elif ch == "," and not in_quote:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            key, _, val = part.partition(":")
            key = key.strip()
            val = val.strip().strip("'")
            if key == "id":
                result["id"] = int(val)
            elif key == "severity":
                result["severity"] = SEVERITY_MAP.get(val.upper(), "medium")
            elif key == "msg":
                result["msg"] = val
            elif key == "tag":
                tags.append(val)
            elif key == "ver":
                result["ver"] = val
            elif key == "phase":
                result["phase"] = val
            # skip setvar, logdata, t:, capture, multiMatch, etc.
        else:
            # bare keyword actions
            bare = part.strip()
            if bare in ("block", "deny"):
                result["action"] = "block"
            elif bare == "pass":
                result["action_raw"] = "pass"
            elif bare == "log":
                result.setdefault("action", "log")
            elif bare == "nolog":
                result["nolog"] = True

    result["tags"] = tags
    return result


def extract_paranoia_level(tags: list[str]) -> int:
    """Extract paranoia level from tag list."""
    for tag in tags:
        m = re.search(r"paranoia-level/(\d)", tag)
        if m:
            return int(m.group(1))
    return 1


def map_variables_to_field(variables_str: str) -> str:
    """Map ModSecurity variable expression to prx-waf field."""
    # Specific single-variable headers first
    if "User-Agent" in variables_str and "REQUEST_HEADERS" in variables_str:
        vars_list = [v.strip() for v in re.split(r"[|&]", variables_str)]
        if len(vars_list) == 1 or all(
            "User-Agent" in v or "REQUEST_HEADERS:User-Agent" in v
            for v in vars_list if v
        ):
            return "user_agent"

    # Determine field based on what variable groups are present
    has_path = bool(re.search(r"\bREQUEST_URI\b|\bREQUEST_URI_RAW\b|\bREQUEST_BASENAME\b|\bREQUEST_FILENAME\b|\bREQUEST_LINE\b", variables_str))
    has_args = bool(re.search(r"\bARGS\b|\bARGS_NAMES\b|\bARGS_GET\b", variables_str))
    has_body = bool(re.search(r"\bREQUEST_BODY\b|\bARGS_POST\b|\bFILES\b|\bXML\b", variables_str))
    has_headers = bool(re.search(r"\bREQUEST_HEADERS\b", variables_str))
    has_cookies = bool(re.search(r"\bREQUEST_COOKIES\b", variables_str))
    has_method = bool(re.search(r"\bREQUEST_METHOD\b", variables_str))
    has_response = bool(re.search(r"\bRESPONSE_BODY\b|\bRESPONSE_HEADERS\b|\bRESPONSE_STATUS\b", variables_str))

    total = sum([has_path, has_args, has_body, has_headers, has_cookies, has_method, has_response])

    if total >= 3:
        return "all"
    if total == 2:
        if has_args and has_body:
            return "all"
        if has_args and has_cookies:
            return "all"
        if has_headers and has_cookies:
            return "all"
        if has_path and (has_args or has_body):
            return "all"
        return "all"
    if has_method:
        return "method"
    if has_path:
        return "path"
    if has_args:
        return "query"
    if has_body:
        return "body"
    if has_headers:
        return "headers"
    if has_cookies:
        return "cookies"
    if has_response:
        return "body"
    return "all"


def parse_operator(op_str: str) -> tuple[str, str]:
    """Parse operator string like '@rx pattern' or '@pmFromFile file.data'.
    Returns (operator, value)."""
    op_str = op_str.strip()

    if op_str.startswith("@detectSQLi"):
        return "detect_sqli", ""
    if op_str.startswith("@detectXSS"):
        return "detect_xss", ""
    if op_str.startswith("@pmFromFile"):
        data_file = op_str[len("@pmFromFile"):].strip()
        return "pm_from_file", data_file
    if op_str.startswith("@pm "):
        pattern = op_str[4:].strip()
        return "pm", pattern
    if op_str.startswith("@rx "):
        return "regex", op_str[4:]
    if op_str.startswith("@gt "):
        return "gt", op_str[4:].strip()
    if op_str.startswith("@lt "):
        return "lt", op_str[4:].strip()
    if op_str.startswith("@ge "):
        return "gt", op_str[4:].strip()
    if op_str.startswith("@le "):
        return "lt", op_str[4:].strip()
    if op_str.startswith("@contains "):
        return "contains", op_str[len("@contains "):].strip()
    if op_str.startswith("@beginsWith "):
        return "regex", "^" + re.escape(op_str[len("@beginsWith "):].strip())
    if op_str.startswith("@endsWith "):
        val = op_str[len("@endsWith "):].strip()
        return "regex", re.escape(val) + "$"
    if op_str.startswith("@streq "):
        val = op_str[len("@streq "):].strip()
        return "regex", "^" + re.escape(val) + "$"
    if op_str.startswith("@within "):
        val = op_str[len("@within "):].strip()
        return "contains", val
    if op_str.startswith("@ipMatch "):
        return "contains", op_str[len("@ipMatch "):].strip()
    # Default: treat as regex
    return "regex", op_str


def is_skip_rule(logical_line: str) -> bool:
    """Return True if this rule line should be skipped (gate/control rules)."""
    if not logical_line.strip().startswith("SecRule"):
        return True
    for pat in SKIP_PATTERNS:
        if re.search(pat, logical_line):
            return True
    return False


def parse_secrule_line(line: str) -> Optional[dict]:
    """
    Parse a single logical SecRule line.
    SecRule VARIABLES "OPERATOR" "ACTIONS"
    Returns None if rule should be skipped.
    """
    line = line.strip()
    if not line.startswith("SecRule "):
        return None

    # Remove 'SecRule ' prefix
    rest = line[8:].strip()

    # Extract VARIABLES (up to first quote)
    quote_pos = rest.find('"')
    if quote_pos == -1:
        return None
    variables_str = rest[:quote_pos].strip()
    rest = rest[quote_pos:]

    # Extract OPERATOR string (content of first quoted section)
    try:
        op_end = rest.index('"', 1)
    except ValueError:
        return None
    operator_str = rest[1:op_end]
    rest = rest[op_end + 1:].strip()

    # Extract ACTIONS string (content of second quoted section)
    if not rest.startswith('"'):
        return None
    try:
        act_end = rest.index('"', 1)
    except ValueError:
        return None
    actions_str = rest[1:act_end]

    # Parse actions
    actions = parse_actions_str(actions_str)

    # Skip if no ID
    if "id" not in actions:
        return None

    rule_id = actions["id"]

    # Skip paranoia gate rules (skipAfter in actions or TX variable checks)
    if "skipAfter" in actions_str:
        return None
    if "TX:DETECTION_PARANOIA_LEVEL" in variables_str or "TX:EXECUTING_PARANOIA_LEVEL" in variables_str:
        return None
    if "TX:" in variables_str and "TX:ANOMALY_SCORE" not in variables_str:
        return None

    # Skip pure scoring / pass rules with nolog
    if actions.get("nolog") and actions.get("action_raw") == "pass":
        return None

    # Parse operator
    operator, value = parse_operator(operator_str)

    # Map variables to field
    field = map_variables_to_field(variables_str)

    # Determine action
    action = actions.get("action", "block")
    if action == "pass" or actions.get("action_raw") == "pass":
        action = "pass"

    # Paranoia level
    paranoia = extract_paranoia_level(actions.get("tags", []))

    # Severity
    severity = actions.get("severity", "medium")

    # Build clean tags (exclude internal CRS meta-tags)
    skip_tag_prefixes = ("OWASP_CRS", "capec/", "ver:", "paranoia-level/", "application-", "language-", "platform-")
    clean_tags = ["owasp-crs"]
    for tag in actions.get("tags", []):
        if any(tag.startswith(p) or tag == p for p in skip_tag_prefixes):
            continue
        if tag.lower().startswith("attack-"):
            clean_tags.append(tag.lower().replace("attack-", ""))
        elif "/" not in tag:
            clean_tags.append(tag.lower())

    # Deduplicate
    seen = set()
    deduped_tags = []
    for t in clean_tags:
        if t not in seen:
            seen.add(t)
            deduped_tags.append(t)

    msg = actions.get("msg", f"Rule {rule_id}")

    return {
        "crs_id": rule_id,
        "msg": msg,
        "field": field,
        "operator": operator,
        "value": value,
        "action": action,
        "severity": severity,
        "paranoia": paranoia,
        "tags_raw": deduped_tags,
    }


def build_rule_id(crs_id: int, category_prefix: str) -> str:
    """Build a string rule ID from CRS numeric ID."""
    return f"{category_prefix}-{crs_id}"


CATEGORY_ID_PREFIX = {
    "scanner": "CRS-SCANNER",
    "protocol": "CRS-PROTO",
    "lfi": "CRS-LFI",
    "rfi": "CRS-RFI",
    "rce": "CRS-RCE",
    "php": "CRS-PHP",
    "generic": "CRS-GENERIC",
    "xss": "CRS-XSS",
    "sqli": "CRS-SQLI",
    "session": "CRS-SESSION",
    "java": "CRS-JAVA",
    "data-leakage": "CRS-RESP",
    "web-shell": "CRS-RESP",
}


def convert_conf_file(
    conf_path: Path,
    output_dir: Path,
    category: str,
    yaml_filename: str,
    data_dir: Optional[Path] = None,
) -> int:
    """Convert a single .conf file to YAML. Returns number of rules written."""
    text = conf_path.read_text(encoding="utf-8", errors="replace")
    logical_lines = join_continuation_lines(text)

    prefix = CATEGORY_ID_PREFIX.get(category, "CRS")
    rules = []

    for line in logical_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if is_skip_rule(line):
            continue

        parsed = parse_secrule_line(line)
        if parsed is None:
            continue

        crs_id = parsed["crs_id"]
        rule_id = f"{prefix}-{crs_id}"

        # Build value: if pm_from_file, reference data file
        value = parsed["value"]
        if parsed["operator"] == "pm_from_file" and data_dir is not None:
            # value is the filename; keep it as-is (relative to data/)
            pass

        rule = {
            "id": rule_id,
            "name": parsed["msg"],
            "category": category,
            "severity": parsed["severity"],
            "paranoia": parsed["paranoia"],
            "field": parsed["field"],
            "operator": parsed["operator"],
            "value": value,
            "action": parsed["action"],
            "tags": parsed["tags_raw"],
            "crs_id": crs_id,
        }
        rules.append(rule)

    if not rules:
        return 0

    output_path = output_dir / yaml_filename
    doc = {
        "version": "1.0",
        "description": f"OWASP CRS rules converted from {conf_path.name}",
        "source": "OWASP Core Rule Set v4.x (https://github.com/coreruleset/coreruleset)",
        "license": "Apache-2.0",
        "rules": rules,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        yaml.dump(doc, f, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)

    return len(rules)


def convert_directory(
    input_dir: Path,
    output_dir: Path,
    data_dir: Optional[Path] = None,
) -> dict[str, int]:
    """Convert all known .conf files in input_dir. Returns {yaml_name: rule_count}."""
    results = {}
    for conf_name, yaml_name in CONF_TO_YAML.items():
        conf_path = input_dir / conf_name
        if not conf_path.exists():
            continue
        category = CONF_TO_CATEGORY.get(conf_name, "generic")
        count = convert_conf_file(conf_path, output_dir, category, yaml_name, data_dir)
        if count > 0:
            results[yaml_name] = count
            print(f"  {conf_name} → {yaml_name}: {count} rules")
        else:
            print(f"  {conf_name} → {yaml_name}: (no convertible rules)")
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert ModSecurity SecRule files to prx-waf YAML format"
    )
    parser.add_argument("input", help="Input directory (CRS rules/) or single .conf file")
    parser.add_argument("output", help="Output directory for YAML files")
    parser.add_argument(
        "--data-dir",
        help="Directory to look for .data files (for pm_from_file references)",
        default=None,
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)

    data_dir = Path(args.data_dir) if args.data_dir else None

    if input_path.is_dir():
        print(f"Converting directory: {input_path}")
        results = convert_directory(input_path, output_path, data_dir)
        total = sum(results.values())
        print(f"\nTotal: {total} rules converted across {len(results)} files")
    elif input_path.is_file():
        conf_name = input_path.name
        yaml_name = CONF_TO_YAML.get(conf_name, conf_name.replace(".conf", ".yaml"))
        category = CONF_TO_CATEGORY.get(conf_name, "generic")
        count = convert_conf_file(input_path, output_path, category, yaml_name, data_dir)
        print(f"Converted {count} rules → {output_path / yaml_name}")
    else:
        print(f"Error: {input_path} does not exist", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
