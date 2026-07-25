#!/usr/bin/env python3
"""
modsec2yaml.py - Convert ModSecurity SecRule .conf files to prx-waf YAML format.

Usage:
    python3 tools/modsec2yaml.py /tmp/owasp-crs/rules/ rules/owasp-crs/
    python3 tools/modsec2yaml.py /tmp/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf rules/owasp-crs/sqli.yaml
"""

import re
import sys
import os
import glob
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)


# ── File → output YAML name + description ────────────────────────────────────

FILE_MAP = {
    "REQUEST-913": ("scanner-detection.yaml",  "Scanner Detection",          "scanner",          "scanner-detection"),
    "REQUEST-920": ("protocol-enforcement.yaml","Protocol Enforcement",       "protocol",         "protocol-enforcement"),
    "REQUEST-921": ("protocol-attack.yaml",     "Protocol Attack",            "protocol-attack",  "protocol-attack"),
    "REQUEST-922": ("multipart-attack.yaml",    "Multipart/Form-Data Bypass", "multipart",        "multipart-attack"),
    "REQUEST-930": ("lfi.yaml",                 "Local File Inclusion",       "lfi",              "lfi"),
    "REQUEST-931": ("rfi.yaml",                 "Remote File Inclusion",      "rfi",              "rfi"),
    "REQUEST-932": ("rce.yaml",                 "Remote Code Execution",      "rce",              "rce"),
    "REQUEST-933": ("php-injection.yaml",       "PHP Injection",              "php-injection",    "php-injection"),
    "REQUEST-934": ("generic-attack.yaml",      "Generic Attack",             "generic-attack",   "generic-attack"),
    "REQUEST-941": ("xss.yaml",                 "Cross-Site Scripting (XSS)", "xss",              "xss"),
    "REQUEST-942": ("sqli.yaml",                "SQL Injection",              "sqli",             "sqli"),
    "REQUEST-943": ("session-fixation.yaml",    "Session Fixation",           "session-fixation", "session-fixation"),
    "REQUEST-944": ("java-injection.yaml",      "Java Injection",             "java-injection",   "java-injection"),
    "RESPONSE-950": ("data-leakage.yaml",       "Data Leakage",               "data-leakage",     "data-leakage"),
    "RESPONSE-951": ("data-leakage-sql.yaml",   "SQL Data Leakage",           "data-leakage",     "data-leakage-sql"),
    "RESPONSE-952": ("data-leakage-java.yaml",  "Java Data Leakage",          "data-leakage",     "data-leakage-java"),
    "RESPONSE-953": ("data-leakage-php.yaml",   "PHP Data Leakage",           "data-leakage",     "data-leakage-php"),
    "RESPONSE-954": ("data-leakage-iis.yaml",   "IIS Data Leakage",           "data-leakage",     "data-leakage-iis"),
    "RESPONSE-955": ("web-shells.yaml",         "Web Shells",                 "rce",              "web-shells"),
    "RESPONSE-956": ("data-leakage-ruby.yaml",  "Ruby Data Leakage",          "data-leakage",     "data-leakage-ruby"),
}

# ── Attack tag → category ─────────────────────────────────────────────────────

TAG_CATEGORY = {
    "attack-sqli":              "sqli",
    "attack-xss":               "xss",
    "attack-rfi":               "rfi",
    "attack-lfi":               "lfi",
    "attack-rce":               "rce",
    "attack-php-injection":     "php-injection",
    "attack-injection-generic": "generic-attack",
    "attack-session-fixation":  "session-fixation",
    "attack-java":              "java-injection",
    "attack-reputation-scanner":"scanner-detection",
    "attack-protocol":          "protocol-attack",
    "attack-multipart":         "multipart-attack",
    "data-leakage":             "data-leakage",
}

# ── Variable → field mapping ──────────────────────────────────────────────────
#
# Every ModSecurity variable is first resolved to a *field name*, then field
# names are grouped into coarse *surfaces* so that a rule listing several
# variables can be given the narrowest engine field that still covers them.
#
# Two invariants matter here, both learned the hard way:
#
#   1. An unrecognised variable must never become `all`.  `all` is the widest
#      field the engine has (path + query + body + every header value), so
#      "we do not know what this is" silently turning into "scan everything"
#      is a fail-open that manufactures false positives.  Unrecognised
#      variables get an `unmapped_*` sentinel instead: the engine has no such
#      field, so the rule is rejected at load time and named in the startup
#      WARN.  Nothing is scanned that the upstream rule did not ask for, and
#      the gap is visible to whoever maintains the mapping.
#
#   2. A rule that names several variables gets a `+`-joined surface list
#      (`query+body+cookies`), not the catch-all `all`.  `all` walks every
#      request header value, and CRS patterns are not written expecting that:
#      CRS-933150 matches the PHP function name `urlencode`, a substring of
#      `Content-Type: application/x-www-form-urlencoded`, and CRS-941130
#      matches `xhtml`, a substring of the `Accept` header every browser
#      sends.  `all` is emitted only when the upstream list really is the
#      whole request.

# Field names the engine can actually evaluate.  Mirrors `Field::parse` in
# crates/waf-engine/src/checks/owasp.rs — keep the two in step.
ENGINE_FIELDS = {
    "all",
    "method",
    "path",
    "path_raw",
    "query",
    "body",
    "args",
    "args_get",
    "args_post",
    "args_names",
    "args_get_names",
    "args_post_names",
    "content_length",
    "content_type",
    "header_content_type",
    "user_agent",
    "header_user_agent",
    "path_length",
    "query_arg_count",
    "headers",
    "cookies",
    "cookies_names",
    "header_referer",
    "header_host",
    "header_range",
}

UNMAPPED_PREFIX = "unmapped_"

# Request surfaces an engine field reads.  Mirrors `Surfaces` in
# crates/waf-engine/src/checks/owasp.rs; the order below is the canonical order
# surface names appear in a composite field name.
#
# `args_*` and `cookies*` are *collection member* surfaces: the engine runs the
# rule once per parameter / per cookie.  `query` and `body` are *whole* surfaces
# — one string covering everything — and back only the ModSecurity variables
# that really are one string (`QUERY_STRING`, `REQUEST_BODY`, `XML:/*`).
SURFACE_ORDER = [
    "path",
    "path_raw",
    "query",
    "args_get",
    "args_post",
    "args_get_names",
    "args_post_names",
    "body",
    "cookies",
    "cookies_names",
    "headers",
    "user_agent",
    "referer",
]

# Atomic surface sets that collapse into one aggregate name, so there is exactly
# one spelling per meaning.  Mirrors `Surfaces::NAMED` in owasp.rs.
SURFACE_AGGREGATES = [
    (frozenset({"args_get", "args_post"}), "args"),
    (frozenset({"args_get_names", "args_post_names"}), "args_names"),
]

# `headers` here means "every header value"; a field naming one specific header
# contributes only that header's surface.  Scalar/derived fields (`method`,
# `content_length`, ...) never take part in a composite and are absent.
FIELD_SURFACES = {
    "path":              ("path",),
    "path_raw":          ("path_raw",),
    "query":             ("query",),
    "body":              ("body",),
    "args":              ("args_get", "args_post"),
    "args_get":          ("args_get",),
    "args_post":         ("args_post",),
    "args_names":        ("args_get_names", "args_post_names"),
    "args_get_names":    ("args_get_names",),
    "args_post_names":   ("args_post_names",),
    "cookies":           ("cookies",),
    "cookies_names":     ("cookies_names",),
    "headers":           ("headers",),
    "user_agent":        ("user_agent",),
    "header_user_agent": ("user_agent",),
    "header_referer":    ("referer",),
}

# Coarse request surface per engine field, kept for callers that only need a
# single label.
FIELD_SURFACE = {field: surfaces[0] for field, surfaces in FIELD_SURFACES.items()}

# `XML:/*` selects nodes of a body parsed as XML.  The engine has no XML node
# accessor, so the variable is approximated by the whole-`body` surface — which
# is wider than upstream for every body that is not XML.
#
# The approximation is withheld from rules whose variable list is *only* the
# ARGS family (`ARGS|ARGS_NAMES|XML:/*`).  CRS calls those out in their own
# names — "Restricted SQL Character Anomaly Detection (args)" — because they
# describe one parameter value, and a whole JSON body trivially clears
# CRS-942430's "twelve special characters" bar.  Those rules keep the parameter
# members they asked for; widening them to the raw body would trade one class of
# false positive for two.  A list that also names cookies or headers already
# scans several surfaces at once, so the body approximation stays there.
ARGS_FAMILY_PREFIXES = ("ARGS", "QUERY_STRING", "XML:")


def _surface_field(surfaces) -> str:
    """Canonical field name for a set of surfaces."""
    remaining = set(surfaces)
    if not remaining:
        return "all"
    if remaining == {"path", "query", "body", "cookies", "headers"}:
        return "all"

    # Collapse `args_get`+`args_post` into `args` (and the names pair likewise)
    # before ordering, so the composite reads the way the CRS variable list does.
    named = {}
    for atoms, aggregate in SURFACE_AGGREGATES:
        if atoms <= remaining:
            remaining -= atoms
            named[aggregate] = min(SURFACE_ORDER.index(a) for a in atoms)
    for atom in remaining:
        named[atom] = SURFACE_ORDER.index(atom)

    ordered = [name for name, _ in sorted(named.items(), key=lambda item: item[1])]
    if len(ordered) == 1:
        single = {"headers": "headers", "user_agent": "user_agent", "referer": "header_referer"}
        return single.get(ordered[0], ordered[0])
    return "+".join(ordered)


def _sentinel(var: str) -> str:
    """A field name the engine is guaranteed to reject, naming the variable.

    `&VAR` (count of) and `!VAR` (exclusion) keep a readable prefix so the
    startup WARN says which ModSecurity construct is missing, not just which
    collection.
    """
    v = var.strip()
    prefix = ""
    while v[:1] in ("&", "!"):
        prefix += "count_" if v[0] == "&" else "not_"
        v = v[1:]
    slug = re.sub(r"[^a-z0-9]+", "_", (prefix + v).lower()).strip("_")
    return UNMAPPED_PREFIX + (slug or "variable")


def map_variables(var_str: str) -> str:
    """Map a ModSecurity variable list to a single prx-waf field name."""
    parts = [p.strip() for p in var_str.strip().strip('"').split("|") if p.strip()]

    # `!VAR` removes members from the collection being scanned.  It can only
    # narrow a rule, never widen it, and the engine has no exclusion syntax, so
    # it contributes no field of its own.
    positives = [p for p in parts if not p.startswith("!")]
    if not positives:
        return _sentinel(var_str)

    if len(positives) == 1:
        return _single_var_map(positives[0])

    fields = [_single_var_map(p) for p in positives]

    # A rule that touches any TX/IP/GEO collection is a CRS bookkeeping rule;
    # the caller drops it wholesale.
    if any(f == "tx" for f in fields):
        return "tx"

    supported = [f for f in fields if f in ENGINE_FIELDS]
    if not supported:
        # Nothing in this rule is reachable.  Name the first gap.
        return next(f for f in fields if f not in ENGINE_FIELDS)

    # Variables the engine cannot reach are simply not scanned.  Dropping them
    # narrows the rule, which is safe; widening to cover them is not.
    if len(set(supported)) == 1:
        return supported[0]

    surfaces = set()
    args_only = True
    for token, field in zip(positives, fields):
        if field not in ENGINE_FIELDS:
            continue
        surfaces.update(FIELD_SURFACES.get(field, ()))
        if not token.strip().upper().startswith(ARGS_FAMILY_PREFIXES):
            args_only = False
    if args_only:
        surfaces.discard("body")
    if not surfaces:
        # Only scalar/derived fields (e.g. two size limits); nothing composite
        # to express, so keep the first one rather than inventing a scan.
        return supported[0]
    return _surface_field(surfaces)


def _var_category(v: str) -> str:
    """Coarse request surface a single ModSecurity variable belongs to."""
    return FIELD_SURFACE.get(_single_var_map(v), "other")


def _single_var_map(v: str) -> str:
    """Map one ModSecurity variable to an engine field, or to a sentinel."""
    v = v.strip().upper()

    # `&VAR` is the *count* of a collection, not its contents.  The engine has
    # no counting operator, so these can only be reported as unmapped — mapping
    # `&REQUEST_HEADERS:Range` to `header_range` would turn "a Range header is
    # present" into "the Range header matches", a different rule.
    if v.startswith("&"):
        # TX bookkeeping counts are dropped by the caller, not warned about.
        if v.startswith("&TX:") or v.startswith("&IP:") or v.startswith("&GEO:"):
            return "tx"
        return _sentinel(v)

    # `REQUEST_URI` / `REQUEST_FILENAME` / `REQUEST_BASENAME` / `PATH_INFO` are
    # the *decoded* URI: ModSecurity percent-decodes and path-normalises them
    # before a rule runs.  `REQUEST_URI_RAW` and `REQUEST_LINE` are the bytes
    # off the wire, and CRS relies on the difference — CRS-920610 flags a raw
    # `#` in `REQUEST_URI_RAW` precisely because a properly escaped `%23` is
    # legal, and CRS-930100's pattern is a catalogue of `%2f` / `%c0%af`
    # spellings that only exist before decoding.  Mapping both onto one field
    # forced the engine to pick a single answer for two opposite requirements.
    if v in ("REQUEST_URI", "REQUEST_FILENAME", "REQUEST_BASENAME", "PATH_INFO"):
        return "path"
    if v in ("REQUEST_URI_RAW", "REQUEST_LINE"):
        return "path_raw"
    # The ARGS family is a *collection*: upstream evaluates the rule once per
    # parameter, and the engine now does the same.  Folding it onto the whole
    # query string is what made CRS-942130 read `?tab=tab`'s own `name=value`
    # separator as a `1=1` tautology, kept CRS-942440's `^(?:JWT|token)$`
    # exemption from ever being true, and left CRS-943110's anchored
    # `ARGS_NAMES` pattern unable to match anything at all.
    #
    # `QUERY_STRING` is *not* part of the family: upstream really does hand that
    # variable the whole undivided query string.
    if v in ("ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST",
             "ARGS_GET_NAMES", "ARGS_POST_NAMES"):
        return v.lower()
    if v == "QUERY_STRING":
        return "query"
    # XML:/... selects nodes of the request body parsed as XML.
    if v.startswith("XML:"):
        return "body"
    if v == "REQUEST_BODY":
        return "body"
    if v == "REQUEST_METHOD":
        return "method"
    if v == "REQUEST_HEADERS:USER-AGENT":
        return "user_agent"
    # Headers the engine exposes under a name of its own rather than as
    # `header_<name>`.
    if v == "REQUEST_HEADERS:CONTENT-LENGTH":
        return "content_length"
    if v == "REQUEST_HEADERS:CONTENT-TYPE":
        return "content_type"
    if v.startswith("REQUEST_HEADERS:"):
        # Specific header.  `header_<name>` is only evaluable for the handful
        # of headers `Field::parse` knows; the rest are rejected by name, which
        # is exactly the signal a maintainer needs.
        header = v[len("REQUEST_HEADERS:"):].lower().replace("-", "_")
        return f"header_{header}"
    if v in ("REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"):
        return "headers"
    if v.startswith("REQUEST_COOKIES_NAMES"):
        return "cookies_names"
    if v.startswith("REQUEST_COOKIES"):
        return "cookies"
    if v.startswith("RESPONSE_BODY"):
        return "response_body"
    # Response-phase variables keep a response-phase field name.  The engine now
    # reads both of these (`Field::ResponseBody` / `Field::ResponseStatus`) and
    # routes any rule naming one of them into the response pipeline, scored
    # against the outbound threshold.  Anything else response-side stays
    # unmapped, so it is rejected loudly rather than run against the request.
    if v.startswith("RESPONSE_STATUS"):
        return "response_status"
    if v.startswith("RESPONSE_HEADERS") or v.startswith("RESPONSE_PROTOCOL"):
        return "response_headers"
    if v.startswith("TX:") or v.startswith("IP:") or v.startswith("GEO:"):
        return "tx"

    # Known-but-unreachable CRS variables.  Listed explicitly so the sentinel
    # names are stable across re-syncs and so this doubles as the "not
    # supported yet" inventory:
    #
    #   MULTIPART_*        multipart part headers / charset — the engine sees
    #                      the raw body, not parsed parts (CRS 922).
    #   FILES, FILES_NAMES uploaded file names (CRS 933110/933220/944140/932180).
    #   MATCHED_VAR(S)     the previous rule's match, chained rules only.
    #   REMOTE_ADDR        available to the engine, but not through Field.
    #   REQBODY_PROCESSOR, UNIQUE_ID, *_COMBINED_SIZE, REQUEST_BODY_LENGTH,
    #   REQUEST_PROTOCOL   no accessor.
    return _sentinel(v)


# ── Operator mapping ──────────────────────────────────────────────────────────

OPERATOR_MAP = {
    "@rx":           "regex",
    "@pmfromfile":   "pm_from_file",
    "@pm":           "contains_any",
    "@detectsqli":   "detect_sqli",
    "@detectxss":    "detect_xss",
    "@gt":           "gt",
    "@lt":           "lt",
    "@ge":           "ge",
    "@le":           "le",
    "@contains":     "contains",
    "@containsword": "contains_word",
    "@streq":        "equals",
    "@within":       "in",
    "@beginswith":   "starts_with",
    "@endswith":     "ends_with",
    "@eq":           "equals",
    "@ipMatch":      "ip_match",
    "@ipmatch":      "ip_match",
    "@ipmatchfromfile": "ip_match_file",
    "@validateutf8encoding": "validate_utf8",
    "@validatebyterange": "validate_byte_range",
    "@verifycc":     "verify_cc",
    "@noMatch":      "no_match",
    "@nomatch":      "no_match",
}


def map_operator(op: str) -> str:
    return OPERATOR_MAP.get(op.lower(), op.lstrip("@"))


# ── Severity mapping ──────────────────────────────────────────────────────────
#
# `severity:` is not decoration: in CRS it *is* the rule's weight. Every rule
# pairs its severity with a matching `setvar:tx.inbound_anomaly_score_plN=
# +%{tx.<severity>_anomaly_score}`, and `REQUEST-949-BLOCKING-EVALUATION.conf`
# denies the request once those add up to `tx.inbound_anomaly_score_threshold`.
# The pairing is exhaustive across CRS v4.25.0 — CRITICAL always adds
# `critical_anomaly_score`, WARNING always adds `warning_anomaly_score`, with no
# cross terms — so carrying the severity through verbatim is enough for the
# engine to reconstruct the score without parsing `setvar`.
#
# The four names below are the only ones CRS uses. The rest of the syslog scale
# is mapped onto them rather than passed through, because the engine scores what
# it is given and an unrecognised name would be scored `critical` by its
# fail-closed default.

SEVERITY_MAP = {
    "emergency": "critical",
    "alert":     "critical",
    "critical":  "critical",
    "error":     "error",
    "warning":   "warning",
    "notice":    "notice",
    "info":      "notice",
    "debug":     "notice",
}


def map_severity(sev: str) -> str:
    """Map a ModSecurity `severity:` onto the four names CRS scores with.

    Defaults to `critical` — fail-closed. A rule whose severity we cannot read
    must not end up cheaper than the author intended; the engine records the
    default in its load summary so the gap is visible.
    """
    return SEVERITY_MAP.get(sev.strip().strip("'\"").lower(), "critical")


# ── Rule parser ───────────────────────────────────────────────────────────────

def join_continuation_lines(text: str) -> list[str]:
    """Join lines ending with backslash into single logical lines."""
    lines = text.splitlines()
    result = []
    current = ""
    for line in lines:
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
        else:
            current += stripped
            result.append(current)
            current = ""
    if current:
        result.append(current)
    return result


# SecRule regex: capture variables, operator+value, and options string
# Both quoted sections may contain backslash-escaped chars (e.g. \" inside @rx)
SECRULE_RE = re.compile(
    r'^\s*SecRule\s+'
    r'((?:"(?:[^"\\]|\\.)*"|[^\s"]+))'   # group 1: variables
    r'\s+'
    r'"((?:[^"\\]|\\.)*)"'               # group 2: operator + value (handles \")
    r'\s+'
    r'"((?:[^"\\]|\\.)*)"'               # group 3: options string
    r'\s*$',
    re.DOTALL
)


def parse_options(opts_str: str) -> dict:
    """Parse comma-separated ModSecurity action/option string into a dict.

    `t:` is accumulated into `_transforms` instead of going through the plain
    `opts[key] = val` path.  Two `ModSecurity` properties make that mandatory:

      * `t:` may appear many times and the list is **ordered** —
        `t:urlDecodeUni,t:lowercase` and `t:lowercase,t:urlDecodeUni` are
        different rules.  A dict entry keeps only the last one, which is how
        every transformation but one used to be dropped on the floor.
      * `t:none` **clears** whatever has accumulated so far (including anything
        a `SecDefaultAction` contributed) rather than being a transformation of
        its own.

    `SecDefaultAction` is checked for completeness: CRS v4 sets only
    `phase`/`log`/`auditlog`/`pass` in `crs-setup.conf.example`, no `t:`, so a
    rule's own list is the whole list and there is nothing to prepend.
    """
    opts = {}
    tags = []
    transforms: list[str] = []

    # Normalize: remove backslash-space sequences, collapse whitespace
    opts_str = re.sub(r'\\\s+', '', opts_str)
    opts_str = re.sub(r'\s+', ' ', opts_str).strip()

    # Split on commas NOT inside single quotes
    parts = _split_options(opts_str)

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # key:'value' or key:"value" or key:value or just keyword
        m = re.match(r'^(\w+)\s*:\s*\'((?:[^\'\\]|\\.)*)\'$', part)
        if m:
            key, val = m.group(1).lower(), m.group(2)
        else:
            m = re.match(r'^(\w+)\s*:\s*"((?:[^"\\]|\\.)*)"$', part)
            if m:
                key, val = m.group(1).lower(), m.group(2)
            else:
                m = re.match(r'^(\w+)\s*:\s*(.+)$', part, re.DOTALL)
                if m:
                    key = m.group(1).lower()
                    val = m.group(2).strip().strip("'\"")
                else:
                    # bare keyword
                    key = part.lower().strip()
                    val = True

        if key == "tag":
            tags.append(val)
        elif key == "setvar":
            opts.setdefault("setvars", []).append(val)
        elif key == "t":
            name = val.strip() if isinstance(val, str) else ""
            if name.lower() == "none":
                transforms.clear()
            elif name:
                transforms.append(name)
        else:
            opts[key] = val

    opts["_tags"] = tags
    opts["_transforms"] = transforms
    return opts


def _split_options(s: str) -> list[str]:
    """Split on commas, but not commas inside single quotes."""
    parts = []
    depth = 0
    current = ""
    in_quote = False
    quote_char = None

    for ch in s:
        if not in_quote and ch in ("'", '"'):
            in_quote = True
            quote_char = ch
            current += ch
        elif in_quote and ch == quote_char:
            in_quote = False
            quote_char = None
            current += ch
        elif not in_quote and ch == ",":
            parts.append(current)
            current = ""
        else:
            current += ch

    if current:
        parts.append(current)
    return parts


def should_skip_rule(variables: str, operator: str, opts: dict) -> tuple[bool, str]:
    """
    Return (True, reason) if this rule should be skipped.
    """
    action = opts.get("action", "")
    # Bare 'pass' or 'block' keywords
    is_pass = "pass" in opts
    is_block = "block" in opts or "deny" in opts
    is_nolog = "nolog" in opts

    # 1. Paranoia gate rules (skipAfter)
    skip_after = opts.get("skipafter", "")
    if skip_after or "skipafter" in opts:
        return True, "paranoia-gate (skipAfter)"

    # 2. SecMarker - handled at a higher level, but just in case
    vars_upper = variables.upper()

    # 3. TX-only variable manipulation
    if vars_upper.startswith("TX:") or vars_upper.startswith("IP:") or vars_upper.startswith("GEO:"):
        # If it's only a TX variable and just does setvar/pass, skip
        if is_pass or (not is_block and not "deny" in opts):
            return True, "TX-variable gate/manipulation"

    # 4. pass+nolog rules (utility rules with no detection value)
    if is_pass and is_nolog and not is_block:
        return True, "pass+nolog utility rule"

    # 5. Rules with no meaningful action (no block/deny/redirect)
    # Some rules just do setvar without blocking - keep them if they have detection
    # but skip if they're purely pass
    if is_pass and not is_block:
        return True, "pass-only rule"

    # 6. RESPONSE_HEADERS skip rules for compressed content
    if "RESPONSE_HEADERS:CONTENT-ENCODING" in vars_upper and skip_after:
        return True, "response compression skip"

    return False, ""


# ── Chained SecRules ──────────────────────────────────────────────────────────
#
# `SecRule ... "...,chain"` followed by further `SecRule` lines is ONE rule
# whose conditions must all hold.  Emitting only the first condition is never
# a conservative simplification: it always produces a *broader* rule than
# upstream, and for CRS that difference is the whole rule.  Two live examples:
#
#   * CRS-944110's first condition is `@rx (?:runtime|processbuilder)`.  On its
#     own it blocks any request mentioning "runtime"; the chained condition
#     requires the same value to also contain `unmarshaller|base64data|java.`,
#     i.e. an actual Java deserialization payload.
#   * CRS-942130 captures the two words either side of `=` and only fires when
#     the chained `TX:1 @streq %{TX.2}` says they are identical (a `1=1`
#     tautology).  Without it the rule reads "block any `word = word`".
#
# So a chain is either emitted in full or the rule is refused outright by
# giving it an `unmapped_chained_*` field the engine cannot resolve.

# Engine operators, mirroring `Loader::compile_condition` in
# crates/waf-engine/src/checks/owasp.rs — keep the two in step.
ENGINE_OPERATORS = {
    "regex",
    "contains",
    "contains_any",
    "pm_from_file",
    "equals",
    "starts_with",
    "ends_with",
    "not_in",
    "gt",
    "lt",
    "detect_sqli",
    "detect_xss",
}

# Operators whose value is a comparison operand and may therefore carry a
# `%{...}` macro.  A macro inside a regex is a different thing entirely and is
# always refused.
OPERAND_OPERATORS = {"contains", "equals", "starts_with", "ends_with"}

# Headers `&REQUEST_HEADERS:<name>` may be mapped to a `count_header_<name>`
# presence test.
#
# Deliberately minimal.  The engine can count any header it can read, but
# turning a `&VAR` test into an enforced rule changes what the rule set blocks:
# CRS-921230 is `&REQUEST_HEADERS:Range @gt 0` at PL2+, so adding "range" here
# would start blocking every byte-range media request.  Add a header only
# together with false-positive probes for the rules it activates.
COUNT_MAPPED_HEADERS = {"referer"}

MACRO_RE = re.compile(r"%\{([^}]*)\}")
TX_INDEX_RE = re.compile(r"^TX:(\d+)$", re.IGNORECASE)
COUNT_HEADER_RE = re.compile(r"^&REQUEST_HEADERS:([\w-]+)$", re.IGNORECASE)
MATCHED_VALUE_VARS = {"MATCHED_VAR", "MATCHED_VARS"}
MATCHED_NAME_VARS = {"MATCHED_VAR_NAME", "MATCHED_VARS_NAMES"}

# A chain child may omit the trailing action string (`SecRule VAR "@rx x"`).
SECRULE_CHILD_RE = re.compile(
    r'^\s*SecRule\s+'
    r'((?:"(?:[^"\\]|\\.)*"|[^\s"]+))'
    r'\s+'
    r'"((?:[^"\\]|\\.)*)"'
    r'(?:\s+"((?:[^"\\]|\\.)*)")?'
    r'\s*$',
    re.DOTALL
)


class ChainUnsupported(Exception):
    """A chain condition this converter cannot express faithfully.

    `reason` becomes the `unmapped_chained_<reason>` sentinel field, so the
    engine's startup WARN names the missing ModSecurity construct.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _count_regex_groups(pattern: str) -> int:
    """Number of capturing groups in a PCRE pattern.

    Counted by scanning rather than by compiling: CRS patterns use PCRE syntax
    (`\\x{bc}`, possessive quantifiers) that Python's `re` rejects.
    """
    groups = 0
    in_class = False
    escaped = False
    for i, ch in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
        elif in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "(" and pattern[i + 1: i + 2] != "?":
            groups += 1
    return groups


def _map_chain_variables(var_str: str) -> str:
    """Map a chain child's variable list to an engine condition field."""
    parts = [p.strip() for p in var_str.strip().strip('"').split("|") if p.strip()]
    positives = [p for p in parts if not p.startswith("!")]
    if not positives:
        raise ChainUnsupported("variable")
    upper = [p.upper() for p in positives]

    if any(v in MATCHED_NAME_VARS for v in upper):
        # The *name* of the matched variable; the engine has no parameter
        # names, only values.
        raise ChainUnsupported("matched_var_name")
    if any(v in MATCHED_VALUE_VARS for v in upper):
        # `MATCHED_VARS|XML:/*` and friends: the extra variables are dropped,
        # which narrows the condition to the values the previous condition
        # matched.  Narrowing is safe; widening is not.
        return "matched_value"

    if len(positives) == 1:
        single = upper[0]
        tx = TX_INDEX_RE.match(single)
        if tx:
            return f"tx:{int(tx.group(1))}"
        if single.startswith("TX:") or single.startswith("&TX:"):
            # `TX:content_type`, `TX:/^header_name_920450_/`: variables a
            # `setvar` built earlier in the same rule.  The converter models no
            # variable store, so the condition cannot be reproduced.
            raise ChainUnsupported("tx_variable")
        count = COUNT_HEADER_RE.match(single)
        if count:
            name = count.group(1).lower().replace("-", "_")
            if name in COUNT_MAPPED_HEADERS:
                return f"count_header_{name}"
            raise ChainUnsupported("header_count")

    field = map_variables(var_str)
    if field == "tx":
        raise ChainUnsupported("tx_variable")
    if field not in ENGINE_FIELDS and "+" not in field:
        raise ChainUnsupported("variable")
    return field


def _check_macros(operator: str, value: str, bound_captures: int) -> None:
    """Refuse a value whose `%{...}` macros the engine cannot expand."""
    if "%{" not in value:
        return
    if operator not in OPERAND_OPERATORS:
        raise ChainUnsupported("macro")
    for match in MACRO_RE.finditer(value):
        name = match.group(1).strip().lower()
        if name == "request_headers.host":
            continue
        tx = re.fullmatch(r"tx\.(\d+)", name)
        if tx:
            if int(tx.group(1)) >= bound_captures:
                raise ChainUnsupported("capture")
            continue
        raise ChainUnsupported("macro")


def _collect_chain_children(lines: list[str], index: int) -> list[dict]:
    """Gather the SecRule lines chained onto the rule at `index`."""
    children = []
    cursor = index + 1
    while cursor < len(lines):
        line = lines[cursor].strip()
        cursor += 1
        if not line or line.startswith("#"):
            continue
        if not line.startswith("SecRule"):
            raise ChainUnsupported("directive")
        match = SECRULE_CHILD_RE.match(line)
        if not match:
            raise ChainUnsupported("syntax")
        opts = parse_options((match.group(3) or "").strip())
        if "id" in opts:
            # A child carrying its own id is a new rule: the chain is truncated
            # in the source, which we must not paper over.
            raise ChainUnsupported("syntax")
        children.append({
            "variables": match.group(1).strip().strip('"'),
            "operator": match.group(2).strip(),
            "opts": opts,
        })
        if "chain" not in opts:
            return children
    raise ChainUnsupported("syntax")


# Engine fields whose values are *collection members* — one parameter, one
# cookie — rather than a whole request surface.  A capture-equality chain
# (`TX:1 @streq %{TX.2}`) is only meaningful over one of these; see the note at
# the `args_self_equality` refusal below.  Mirrors the collection bits of
# `Surfaces` in crates/waf-engine/src/checks/owasp.rs.
PER_MEMBER_SURFACES = frozenset({
    "args_get", "args_post", "args_get_names", "args_post_names",
    "cookies", "cookies_names",
})


def _is_per_member_field(field: str) -> bool:
    """Whether every value `field` yields is a single collection member."""
    if not field:
        return False
    atoms = set()
    for token in field.split("+"):
        mapped = FIELD_SURFACES.get(token)
        if mapped is None:
            return False
        atoms.update(mapped)
    return bool(atoms) and atoms <= PER_MEMBER_SURFACES


def build_chain(head_field: str, head_operator: str, head_value: str, head_opts: dict,
                lines: list[str], index: int) -> tuple[list[dict], bool]:
    """Build the YAML chain conditions for the rule at `index`.

    Returns `(conditions, head_capture)`.  Raises `ChainUnsupported` when any
    condition cannot be expressed, in which case the caller must refuse the
    whole rule.
    """
    children = _collect_chain_children(lines, index)

    # Which condition currently supplies tx:0..tx:N — `-1` is the head.
    # Captures are only emitted for the conditions something actually reads.
    bound_captures = 0
    bound_source = None
    capture_providers: dict[int, int] = {}
    used_providers: set[int] = set()

    if "capture" in head_opts and head_operator == "regex":
        bound_captures = _count_regex_groups(head_value) + 1
        bound_source = -1

    conditions = []
    for position, child in enumerate(children):
        field = _map_chain_variables(child["variables"])

        mapped = _map_chain_operator(child["operator"])
        if mapped is None:
            raise ChainUnsupported("syntax")
        negate, operator, value = mapped
        if operator not in ENGINE_OPERATORS:
            raise ChainUnsupported("operator")

        if field.startswith("tx:"):
            if int(field[3:]) >= bound_captures:
                raise ChainUnsupported("capture")
            used_providers.add(bound_source)
            # `TX:1 @streq %{TX.2}` asserts that the two captures are the same
            # word — a tautology such as `1=1` *inside one parameter*
            # (CRS-942130).  It only says that when the head is evaluated one
            # parameter at a time.  Run against a whole `a=1&b=2` query string
            # the `name=value` separator is itself a `word = word` pair, so
            # `?tab=tab` reads as a tautology and the rule becomes a false
            # positive generator; that is why this used to be refused outright.
            #
            # The engine now evaluates the ARGS family per member, so the
            # refusal is scoped to heads that are still whole surfaces.  The
            # *dis*equality form (CRS-942131) never had the problem: a
            # `name=value` separator is not an inequality operator.
            if operator == "equals" and not negate and "%{" in value \
                    and not _is_per_member_field(head_field):
                raise ChainUnsupported("args_self_equality")
        _check_macros(operator, value, bound_captures)
        if "%{" in value and bound_source is not None:
            used_providers.add(bound_source)

        condition = {"field": field, "operator": operator, "value": value}
        # A chain child carries its own `t:` list; `ModSecurity` does not
        # propagate the chain starter's transformations to the links, and CRS
        # relies on that (CRS-920200's starter is untransformed while its link
        # is `t:none,t:length`).
        transforms = child["opts"].get("_transforms") or []
        if transforms:
            condition["transform"] = list(transforms)
        if negate:
            condition["negate"] = True
        conditions.append(condition)

        if "capture" in child["opts"]:
            if operator != "regex":
                raise ChainUnsupported("capture")
            bound_captures = _count_regex_groups(value) + 1
            bound_source = position
            capture_providers[position] = position

    for position in used_providers:
        if position is None:
            raise ChainUnsupported("capture")
        if position >= 0:
            conditions[position]["capture"] = True

    return conditions, -1 in used_providers


def _map_chain_operator(operator_str: str):
    """Split `!@op value` into `(negate, engine_operator, value)`."""
    text = operator_str.strip()
    negate = text.startswith("!")
    if negate:
        text = text[1:].strip()
    match = re.match(r'^(@\w+)\s*(.*)?$', text, re.DOTALL)
    if not match:
        return None
    return negate, map_operator(match.group(1)), (match.group(2) or "").strip()


def extract_rule(variables: str, operator_str: str, opts: dict,
                 default_category: str) -> dict | None:
    """Convert parsed SecRule components into a prx-waf rule dict."""
    rule_id = opts.get("id", "")
    if not rule_id:
        return None

    # msg
    msg = opts.get("msg", f"Rule {rule_id}")
    msg = msg.strip("'\"")

    # severity — the rule's anomaly-score weight, see map_severity()
    severity = map_severity(opts.get("severity", ""))

    # paranoia level from tags
    paranoia = 1
    tags = opts.get("_tags", [])
    for tag in tags:
        m = re.match(r"paranoia-level/(\d+)", tag, re.IGNORECASE)
        if m:
            paranoia = int(m.group(1))
            break

    # category from attack tags
    category = default_category
    for tag in tags:
        tag_lower = tag.lower()
        for attack_tag, cat in TAG_CATEGORY.items():
            if attack_tag in tag_lower:
                category = cat
                break

    # field mapping
    field = map_variables(variables)

    # Skip TX-only fields (internal ModSec vars, not request data)
    if field == "tx":
        return None

    # operator + value
    op_match = re.match(r'^(@\w+)\s*(.*)?$', operator_str.strip(), re.DOTALL)
    if not op_match:
        return None
    op_raw = op_match.group(1)
    op_value = (op_match.group(2) or "").strip()

    operator = map_operator(op_raw)
    value = op_value

    # action
    #
    # `block` and `deny` are not synonyms and collapsing them was the bug this
    # replaces. In ModSecurity `block` means "apply SecDefaultAction", and CRS
    # ships `SecDefaultAction "phase:2,log,auditlog,pass"`
    # (crs-setup.conf.example:98-99) — so a `block` rule contributes its
    # severity to the anomaly score and lets the request through. Only `deny`
    # is unconditional, and in CRS v4.25.0 exactly six rules use it: 901001,
    # 901500 (config errors) and 949110/949111/959100/959101, which *are* the
    # threshold comparison. None of them survives the conversion, so a converted
    # CRS rule should never come out as `deny`; the branch exists for
    # hand-written virtual patches that legitimately must bypass the score.
    if "deny" in opts or "drop" in opts:
        action = "deny"
    elif "block" in opts:
        action = "block"
    elif "pass" in opts:
        action = "log"
    else:
        action = "block"

    # build tags list
    rule_tags = ["owasp-crs"]
    # Add category as tag
    if category and category not in rule_tags:
        rule_tags.append(category)
    # Add specific attack type tags
    for tag in tags:
        tag_lower = tag.lower()
        for attack_tag in TAG_CATEGORY:
            if attack_tag == tag_lower:
                if tag_lower not in rule_tags:
                    rule_tags.append(tag_lower)

    # `capture` / `chain` are filled in by the caller for a chained SecRule and
    # dropped from the emitted YAML otherwise, so a single-condition rule looks
    # exactly as it did before chains existed.
    rule = {
        "id":       f"CRS-{rule_id}",
        "name":     msg,
        "category": category,
        "severity": severity,
        "paranoia": paranoia,
        "field":    field,
        "operator": operator,
        "value":    value,
        # Ordered `t:` chain, `t:none` already applied.  Absent when the rule
        # declares no transformation, which in `ModSecurity` means the value is
        # matched exactly as the parser produced it.
        "transform": list(opts.get("_transforms") or []) or None,
        "capture":  None,
        "chain":    None,
        "action":   action,
        "tags":     rule_tags,
        "crs_id":   int(rule_id),
    }

    return rule


# ── Conf file parser ──────────────────────────────────────────────────────────

def parse_conf_file(path: str, default_category: str) -> list[dict]:
    """Parse a .conf file and return list of prx-waf rule dicts."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    lines = join_continuation_lines(text)
    rules = []
    seen_ids = set()

    for index, raw_line in enumerate(lines):
        line = raw_line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Skip SecMarker
        if line.startswith("SecMarker"):
            continue

        # Only handle SecRule
        if not line.startswith("SecRule"):
            continue

        # Try to parse the SecRule
        m = SECRULE_RE.match(line)
        if not m:
            continue

        variables = m.group(1).strip().strip('"')
        operator_str = m.group(2).strip()
        opts_str = m.group(3).strip()

        opts = parse_options(opts_str)

        # Check if we should skip
        skip, reason = should_skip_rule(variables, operator_str, opts)
        if skip:
            continue

        rule = extract_rule(variables, operator_str, opts, default_category)
        if rule is None:
            # Say so. A SecRule that carries an id and is neither skipped for a
            # stated reason nor converted is a *gap in this converter*, and the
            # one thing it must not be is invisible — the previous generation
            # silently dropped every `!@op` head (CRS-954130) and nobody could
            # tell that from the output.
            dropped_id = opts.get("id", "")
            if dropped_id:
                print(f"  [drop] {os.path.basename(path)} rule {dropped_id}: "
                      f"variables={variables!r} operator={operator_str!r} not expressible")
            continue

        if "chain" in opts:
            try:
                chain, head_capture = build_chain(
                    rule["field"], rule["operator"], rule["value"], opts, lines, index
                )
            except ChainUnsupported as unsupported:
                # Refuse the whole rule rather than enforce its first condition,
                # which is always broader than what upstream declares.
                rule["field"] = f"{UNMAPPED_PREFIX}chained_{unsupported.reason}"
            else:
                if head_capture:
                    rule["capture"] = True
                rule["chain"] = chain

        # Deduplicate
        if rule["crs_id"] in seen_ids:
            continue
        seen_ids.add(rule["crs_id"])

        rules.append({k: v for k, v in rule.items() if v is not None})

    return rules


# ── YAML writer ───────────────────────────────────────────────────────────────

class IndentedDumper(yaml.Dumper):
    """Custom YAML dumper with better formatting."""
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow=flow, indentless=False)


def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    if len(data) > 120:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


IndentedDumper.add_representer(str, _str_representer)


def write_yaml(output_path: str, description: str, source: str,
               rules: list[dict]) -> None:
    """Write prx-waf YAML file."""
    doc = {
        "version":     "1.0",
        "description": description,
        "source":      source,
        "license":     "Apache-2.0",
        "rules":       rules,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        # Write header
        f.write(f"# Auto-generated from OWASP CRS\n")
        f.write(f"# Source: {source}\n")
        f.write(f"# Description: {description}\n")
        f.write(f"# License: Apache-2.0\n")
        f.write(f"# DO NOT EDIT MANUALLY - use modsec2yaml.py to regenerate\n\n")

        yaml.dump(
            doc,
            f,
            Dumper=IndentedDumper,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=4096,
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def detect_file_key(filename: str) -> str | None:
    """Detect which FILE_MAP key matches a conf filename."""
    basename = os.path.basename(filename).upper()
    for key in FILE_MAP:
        if basename.startswith(key.upper()):
            return key
    return None


def convert_single_file(conf_path: str, out_path: str,
                         source: str = "OWASP CRS v4.25.0") -> int:
    """Convert one .conf file to one .yaml file. Returns rule count."""
    file_key = detect_file_key(conf_path)
    if file_key:
        _, description, category, _ = FILE_MAP[file_key]
    else:
        description = os.path.splitext(os.path.basename(conf_path))[0]
        category = "unknown"

    rules = parse_conf_file(conf_path, category)
    write_yaml(out_path, description, source, rules)
    return len(rules)


def convert_directory(rules_dir: str, out_dir: str,
                      source: str = "OWASP CRS v4.25.0") -> dict[str, int]:
    """Convert all matching .conf files in rules_dir to out_dir."""
    os.makedirs(out_dir, exist_ok=True)

    # Find all REQUEST-*.conf and RESPONSE-*.conf
    conf_files = sorted(
        glob.glob(os.path.join(rules_dir, "REQUEST-*.conf")) +
        glob.glob(os.path.join(rules_dir, "RESPONSE-*.conf"))
    )

    results = {}

    for conf_path in conf_files:
        file_key = detect_file_key(conf_path)
        if file_key not in FILE_MAP:
            # Skip files not in our mapping (e.g. BLOCKING-EVALUATION, INITIALIZATION, etc.)
            print(f"  [skip] {os.path.basename(conf_path)} (not in mapping)")
            continue

        out_name, description, category, _ = FILE_MAP[file_key]
        out_path = os.path.join(out_dir, out_name)

        rules = parse_conf_file(conf_path, category)
        write_yaml(out_path, description, source, rules)

        results[out_name] = len(rules)
        print(f"  [ok]   {os.path.basename(conf_path)} → {out_name} ({len(rules)} rules)")

    return results


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_conf_or_dir> <output_yaml_or_dir>")
        sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2]

    source = "OWASP CRS v4.25.0"

    if os.path.isdir(inp):
        print(f"Converting directory: {inp} → {out}")
        results = convert_directory(inp, out, source)
        total = sum(results.values())
        print(f"\nDone. {len(results)} files, {total} total rules.")
    elif os.path.isfile(inp):
        count = convert_single_file(inp, out, source)
        print(f"Done. {count} rules written to {out}")
    else:
        print(f"ERROR: Input not found: {inp}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
