# prx-waf Rules

Rule definitions for the prx-waf Web Application Firewall engine.
Rules are written in a simple YAML format and cover the full spectrum
of common web attacks — from OWASP CRS-derived detections to targeted
CVE virtual patches and custom application-level controls.

---

## Table of Contents

1. [Overview](#overview)
2. [What the running WAF actually loads](#what-the-running-waf-actually-loads)
3. [Quick Start](#quick-start)
4. [Directory Layout](#directory-layout)
5. [Paranoia Levels](#paranoia-levels)
6. [Rule Format Specification](#rule-format-specification)
7. [Writing Custom Rules](#writing-custom-rules)
8. [Updating Rules](#updating-rules)
9. [Validation](#validation)
10. [Statistics](#statistics)
11. [Audit: why the other directories are off](#audit-why-the-other-directories-are-off)
12. [Licensing](#licensing)
13. [Contributing](#contributing)

---

## Overview

prx-waf uses a declarative, YAML-based rule format. Each rule describes:

- **What to inspect** — request field (path, query, body, headers, …)
- **How to match** — operator (regex, contains, detect_sqli, …)
- **What to match** — pattern or value
- **What to do** — action (block, log, allow)

## What the running WAF actually loads

**Exactly one directory: `rules/owasp-crs/`.** It is a hardcoded path
(`crates/waf-engine/src/checks/owasp.rs:53`, `DEFAULT_RULES_DIR`), read once by
`OWASPCheck::new()` during engine startup (`crates/waf-engine/src/engine.rs:141`).

Every other directory below — `advanced/`, `owasp-api/`, `modsecurity/`,
`cve-patches/`, `bot-detection/`, `custom/` — is **not loaded by the running
proxy**, and never has been. `grep -rn "rules/advanced" crates/ --include=*.rs`
returns nothing. There is no configuration switch that turns them on: the
`[rules]` TOML section (`dir` / `sources` / `enable_builtin_*` / `hot_reload`)
is read by the `rules`, `sources` and `bot` **CLI subcommands only** — the
daemon never constructs a `RuleManager`
(`crates/prx-waf/src/main.rs:740-750`). And `RuleManager::load_from_dir`
(`crates/waf-engine/src/rules/manager.rs:360-395`) does not recurse into
sub-directories anyway.

This is not an oversight waiting to be fixed by pointing the loader at the
other directories. Those 275 rules were audited in full against the real
loader and against benign business traffic — see
[Audit: why the other directories are off](#audit-why-the-other-directories-are-off)
below. Most of them **must not** be loaded.

---

## Quick Start

```bash
# Validate all rules before loading
python tools/validate.py rules/

# Sync OWASP CRS to latest release
python tools/sync.py --source owasp-crs --output rules/owasp-crs/ --tag v4.10.0

# Add a custom rule
cp rules/custom/example.yaml rules/custom/myapp.yaml
# Edit myapp.yaml, then validate
python tools/validate.py rules/custom/myapp.yaml
```

---

## Directory Layout

Exactly one of these directories is loaded by the running proxy; the arrows say
which. See [Audit](#audit-why-the-other-directories-are-off) for why the rest
are off.

```
rules/
├── README.md                  ← You are here
├── sync-config.yaml           ← Upstream source configuration
│
├── owasp-crs/                 ← ★ THE ONLY DIRECTORY THE PROXY LOADS
│                                (OWASP ModSecurity Core Rule Set, converted)
│   ├── README.md
│   ├── sqli.yaml              ← SQL injection (CRS 942xxx)
│   ├── xss.yaml               ← Cross-site scripting (CRS 941xxx)
│   ├── rce.yaml               ← Remote code execution (CRS 932xxx)
│   ├── lfi.yaml               ← Local file inclusion (CRS 930xxx)
│   ├── rfi.yaml               ← Remote file inclusion (CRS 931xxx)
│   ├── php-injection.yaml     ← PHP injection (CRS 933xxx)
│   ├── java-injection.yaml    ← Java/EL injection (CRS 944xxx)
│   ├── generic-attack.yaml    ← Node.js, SSI, HTTP splitting (CRS 934xxx)
│   ├── scanner-detection.yaml ← Security scanner UA detection (CRS 913xxx)
│   ├── protocol-enforcement.yaml  ← HTTP protocol compliance (CRS 920xxx)
│   ├── protocol-attack.yaml   ← Request smuggling, CRLF (CRS 921xxx)
│   ├── multipart-attack.yaml  ← Multipart bypass (CRS 922xxx)
│   ├── method-enforcement.yaml    ← HTTP method allowlist (CRS 911xxx)
│   ├── session-fixation.yaml  ← Session fixation (CRS 943xxx)
│   ├── web-shells.yaml        ← Web shell detection (CRS 955xxx)
│   ├── response-*.yaml        ← Response inspection (CRS 950-956xxx)
│   └── data/                  ← Phrase-match wordlists (.data files)
│       ├── scanners-user-agents.data
│       ├── lfi-os-files.data
│       ├── sql-errors.data
│       └── ...                ← 20+ wordlist files
│
├── modsecurity/               ← NOT LOADED — ModSecurity community-inspired rules
│   ├── README.md
│   ├── ip-reputation.yaml     ← Bot/scanner/proxy detection
│   ├── dos-protection.yaml    ← DoS and abnormal request detection
│   ├── data-leakage.yaml      ← PII and credential leak detection
│   └── response-checks.yaml   ← Response inspection
│
├── cve-patches/               ← NOT LOADED — targeted CVE virtual patches
│   ├── README.md
│   ├── 2021-log4shell.yaml    ← CVE-2021-44228, CVE-2021-45046
│   ├── 2022-spring4shell.yaml ← CVE-2022-22965, CVE-2022-22963
│   ├── 2022-text4shell.yaml   ← CVE-2022-42889
│   ├── 2023-moveit.yaml       ← CVE-2023-34362, CVE-2023-36934
│   ├── 2024-recent.yaml       ← 2024 high-profile CVEs
│   └── 2025-recent.yaml       ← 2025 high-profile CVEs
│
├── advanced/                  ← NOT LOADED — advanced attack detection
│   ├── README.md
│   ├── ssrf.yaml              ← Server-Side Request Forgery
│   ├── xxe.yaml               ← XML External Entity injection
│   ├── ssti.yaml              ← Server-Side Template Injection
│   ├── deserialization.yaml   ← Insecure deserialization
│   ├── prototype-pollution.yaml ← JavaScript prototype pollution
│   └── webshell-upload.yaml   ← Webshell upload attempts
│
├── bot-detection/             ← NOT LOADED — bot and crawler detection
│   ├── README.md
│   ├── crawlers.yaml          ← Known web crawlers and scrapers
│   ├── scraping.yaml          ← Automated scraping behavior
│   └── credential-stuffing.yaml ← Credential stuffing detection
│
├── geoip/                     ← README only; geographic rules are not YAML rules
│   └── README.md
│
├── owasp-api/                 ← NOT LOADED — OWASP API Security Top 10
│   ├── README.md
│   ├── broken-auth.yaml       ← API1: Broken Object Level Authorization
│   ├── data-exposure.yaml     ← API3: Excessive Data Exposure
│   ├── injection.yaml         ← API8: Injection
│   ├── mass-assignment.yaml   ← API6: Mass Assignment
│   └── rate-abuse.yaml        ← API4: Lack of Resources & Rate Limiting
│
├── custom/                    ← NOT LOADED — annotated template only
│   ├── README.md
│   └── example.yaml           ← Annotated example rules
│
└── tools/                     ← Maintenance utilities
    ├── modsec2yaml.py         ← Convert ModSecurity .conf → prx-waf YAML
    ├── sync.py                ← Sync rules from upstream sources
    ├── validate.py            ← Validate YAML rule files
    └── requirements.txt       ← Python dependencies
```

---

## Paranoia Levels

Each rule declares a `paranoia` level (1–4) indicating how aggressively
it matches. Higher paranoia levels catch more attacks but increase the
risk of false positives (blocking legitimate traffic).

| Level | Name        | Description                                                   | False Positive Risk |
|-------|-------------|---------------------------------------------------------------|---------------------|
| 1     | Default     | High-confidence rules, production-safe for most applications  | Very low            |
| 2     | Recommended | Broader coverage, minor FP risk on unusual (but valid) input  | Low                 |
| 3     | Aggressive  | Extensive heuristics; requires tuning for your application    | Moderate            |
| 4     | Maximum     | Everything, including speculative patterns; research/lab use  | High                |

**Recommended approach:**
1. Start with paranoia level 1 in production.
2. Monitor logs for false positives.
3. Once stable, enable level 2 rules.
4. Only enable levels 3/4 in environments where you can tune exclusions.

The WAF engine loads rules up to and including the configured paranoia
level. Rules without a `paranoia` field default to level 1.

---

## Rule Format Specification

Every rule file is a YAML document with this top-level structure:

```yaml
version: "1.0"                          # Schema version (string, required)
description: "Short description"        # Human-readable label (string, required)
source: "OWASP CRS v4.25.0"            # Origin of the rules (string, optional)
license: "Apache-2.0"                   # SPDX license identifier (string, optional)

rules:
  - <rule>
  - <rule>
  ...
```

### Rule Schema

```yaml
- id: "CRS-942100"              # Unique string ID across ALL rule files (REQUIRED)
                                # Format: <PREFIX>-<CATEGORY>-<NNN> or <PREFIX>-<NNN>
                                # Examples: CRS-942100, MODSEC-IP-001, CVE-2021-LOG4J-001,
                                #           CUSTOM-API-001

  name: "Rule description"      # Short human-readable name (REQUIRED)
                                # Max ~120 chars; describe what the rule detects.

  category: "sqli"              # Category tag (REQUIRED)
                                # Free-form string; used for filtering and reporting.
                                # Common values: sqli, xss, rce, lfi, rfi, php-injection,
                                # java-injection, scanner, protocol, session-fixation,
                                # data-leakage, dos, access-control, custom

  severity: "critical"          # Severity level (REQUIRED)
                                # One of: critical | high | medium | low | info | notice |
                                #         warning | error | unknown

  paranoia: 1                   # Paranoia level 1-4 (integer, OPTIONAL, default: 1)
                                # Controls how eagerly the rule is activated.

  field: "query+body"           # Which part(s) of the request to inspect (REQUIRED)
                                # Single surface, or several joined with `+`.
                                # See Field Reference below.

  operator: "regex"             # How to match the value (REQUIRED)
                                # See Operator Reference below.

  value: "(?i)select.+from"     # Pattern or threshold to match against (REQUIRED)
                                # For regex: a PCRE-compatible regular expression.
                                # For numeric operators: a number string.
                                # For detect_sqli / detect_xss: "true" or "".
                                # For pm_from_file: filename in owasp-crs/data/.

  action: "block"               # What to do when the rule matches (REQUIRED)
                                # One of: block | log | allow | deny | redirect | drop
                                # Most rules use block (active protection) or
                                # log (monitoring / tuning mode).

  tags:                         # List of string tags (OPTIONAL)
    - "owasp-crs"               # Used for filtering, reporting, and WAF dashboards.
    - "sqli"
    - "attack-sqli"

  crs_id: 942100                # Original CRS numeric ID (integer, OPTIONAL)
                                # Only present on CRS-converted rules.

  reference: "https://..."      # Link to CVE, OWASP article, or rule rationale (OPTIONAL)
```

### Field Reference

| Field              | Inspects                                           |
|--------------------|----------------------------------------------------|
| `path`             | Request URI path (without query string)            |
| `query`            | Query string (all parameters, decoded)             |
| `body`             | Request body (decoded)                             |
| `xml_text`         | Character data of an XML request body, as one value |
| `xml_attrs`        | Each attribute value of an XML request body         |
| `headers`          | All request headers (name: value pairs)            |
| `user_agent`       | User-Agent header only                             |
| `cookies`          | Request cookies                                    |
| `method`           | HTTP method (GET, POST, PUT, …)                    |
| `content_type`     | Content-Type header                                |
| `content_length`   | Content-Length value (numeric comparison)          |
| `path_length`      | Length of the URI path (numeric comparison)        |
| `query_arg_count`  | Number of query parameters (numeric comparison)    |
| `header_referer`   | Referer header only                                |
| `header_host`      | Host request header only (not the matched vhost)   |
| `header_range`     | Range header only                                  |
| `all`              | Path, query, body, cookies and every header value  |

#### Composite fields

A rule that must read several places at once names them joined with `+`, in
this order: `path`, `query`, `body`, `cookies`, `headers`, `user_agent`,
`referer` — for example `query+body+cookies`. `all` is exactly
`path+query+body+cookies+headers`.

Reach for the narrowest list that covers the rule. `all` walks **every request
header value**, and a pattern that is safe on arguments is often not safe
there: CRS-933150 matches the PHP function name `urlencode`, which is a
substring of `Content-Type: application/x-www-form-urlencoded`, and CRS-941130
matches `xhtml`, which every browser sends in `Accept`. Both blocked ordinary
traffic while they carried `all`.

An unknown or duplicated surface name is rejected at load time rather than
quietly scanning less than the rule says.

#### `xml_text` / `xml_attrs` are content-type gated

These are `ModSecurity`'s `XML:/*` and `XML://@*`, and like upstream they are
populated **only** when the request's `Content-Type` is one the XML body
processor claims (`text/xml`, `application/xml`, `application/soap+xml`). A JSON
or plain-text body leaves both empty; a rule that must see such a body names
`body`. They were folded onto `body` until CRS v4.25.0, which handed 154 rules
every byte of every body regardless of content type — do not put them back.

#### Fields the engine cannot evaluate

Rule files may also carry a field the loader deliberately refuses:

| Field                    | Meaning                                                      |
|--------------------------|--------------------------------------------------------------|
| `unmapped_<variable>`    | A `ModSecurity` variable with no accessor (see below)        |
| `geo_iso` / `geo_isp` / `geo_country` / `geo_province` / `geo_city` | Geographic fields. **Not** part of this schema — see [Geographic rules](#geographic-rules-are-not-yaml-rules) |

`response_body` and `response_status` *are* supported and are **not** in this
table: a rule naming either joins the response pipeline (`ResponseCheck`) and
is scored against the separate outbound threshold. 59 of the shipped
`owasp-crs/` rules are response-phase rules.

#### Geographic rules are not YAML rules

`Field::parse` (`crates/waf-engine/src/checks/owasp.rs:809-864`) has no
geographic field, and there is no path from the OWASP phase to `ctx.geo`, so a
YAML rule can never make a decision based on country, ISP or city. Country
blocking is done through the **custom-rules engine**, whose
`ConditionField` enum does have `GeoIso` / `GeoCountry` / `GeoProvince` /
`GeoCity` / `GeoIsp` (`crates/waf-engine/src/rules/engine.rs:36-47`), with
`in_list` / `not_in_list` / `cidr_match` operators, stored in Postgres and
managed over `POST /api/custom-rules`. It needs `[geoip] enabled = true` and
the xdb files (`prx-waf geoip download`).

These rules are counted, rejected, and named in the startup `WARN`, which is
the supported way to record "converted, but not enforceable". Never substitute
`all` for a variable the engine does not support: that turns "we cannot check
this" into "check everything", which is how CRS-922130
(`MULTIPART_PART_HEADERS`) came to block any body containing a word followed by
a colon. Current `unmapped_*` fields, all produced by `tools/modsec2yaml.py`:

| Field                                  | Upstream variable                              |
|----------------------------------------|------------------------------------------------|
| `unmapped_files`                       | `FILES`, `FILES_NAMES`, `REQUEST_HEADERS:X-Filename` |
| `unmapped_multipart_part_headers`      | `MULTIPART_PART_HEADERS`                       |
| `unmapped_count_request_headers_range` | `&REQUEST_HEADERS:Range` (a count, not a value) |
| `unmapped_chained_capture_equality`    | A chained `SecRule TX:1 "@streq %{TX.2}"`      |

### Operator Reference

This is the complete set the loader accepts
(`crates/waf-engine/src/checks/owasp.rs:3067-3096`). Anything else is rejected
at load time as `UnsupportedOperator` — the rule is not silently skipped, it is
named in the startup `WARN`.

| Operator        | `value` type   | Description                                                         |
|-----------------|----------------|---------------------------------------------------------------------|
| `regex`         | string         | Rust `regex` crate. **No lookaround, no backreferences** — see below |
| `contains`      | string         | Field contains the literal string in `value`                        |
| `starts_with`   | string         | Field starts with `value`                                           |
| `ends_with`     | string         | Field ends with `value`                                             |
| `equals`        | string         | Field value exactly equals `value` (case-sensitive)                 |
| `not_in`        | list of strings| Field value is NOT one of the listed values (scalar fields only)    |
| `gt`            | **integer**    | Field value (numeric) is greater than `value`                       |
| `lt`            | **integer**    | Field value (numeric) is less than `value`                          |
| `contains_any`  | string or list | Phrase-match (`@pm`) against an inline phrase set                   |
| `pm_from_file`  | string         | Phrase-match against a wordlist file in `owasp-crs/data/`           |
| `detect_sqli`   | any            | SQL injection detection via libinjection                            |
| `detect_xss`    | any            | XSS detection via libinjection                                      |

`gt` / `lt` take a YAML **integer**. `value: "1024"` is a string and is
rejected as `InvalidValueType`; write `value: 1024`.

The regex engine is `regex`, not PCRE. `(?!…)`, `(?<=…)` and `\1` are
compile errors, and the rule is dropped with `InvalidRegex` at startup.

### Action Reference

| Action                    | Description                                                                       |
|---------------------------|-----------------------------------------------------------------------------------|
| `block` / `score`         | Add this rule's severity to the anomaly score, keep evaluating (upstream `block`) |
| `deny` / `drop` / `reject`| Block immediately, whatever the score is                                          |
| `log` / `pass` / `alert`  | Record the match, contribute nothing — **see [`action: log` is silent](#action-log-is-silent)** |

`block` does **not** mean "deny". It means what `SecDefaultAction` says
upstream, which for CRS is "add to the score and continue". Whether it ends in
a 403 depends on the severity and the threshold: with the shipped numbers a
single `critical` reaches the inbound threshold on its own, and a single
`error` does so in the response phase.

There is no `allow` and no `redirect`; both are rejected at load time.

---

## Writing Custom Rules

1. **Create a new YAML file** in `rules/custom/`:
   ```bash
   cp rules/custom/example.yaml rules/custom/myapp.yaml
   ```

2. **Choose unique IDs** using the `CUSTOM-` prefix:
   ```
   CUSTOM-API-001
   CUSTOM-APP-001
   CUSTOM-BOT-001
   ```

3. **Write your rule** following the schema above. See `rules/custom/example.yaml`
   for fully annotated working examples.

4. **Validate** before deploying:
   ```bash
   python tools/validate.py rules/custom/myapp.yaml
   ```

### Example: Block a Specific Path

```yaml
version: "1.0"
description: "Myapp custom rules"
rules:
  - id: "CUSTOM-APP-001"
    name: "Block Access to Internal Admin API"
    category: "access-control"
    severity: "high"
    paranoia: 1
    field: "path"
    operator: "regex"
    value: "(?i)^/internal/"
    action: "block"
    tags: ["custom", "access-control"]
```

### Example: Log Suspicious User-Agent

```yaml
  - id: "CUSTOM-BOT-001"
    name: "Log Suspicious Automated Tool User-Agents"
    category: "scanner"
    severity: "medium"
    paranoia: 2
    field: "user_agent"
    operator: "regex"
    value: "(?i)(masscan|zgrab|python-requests/|go-http-client)"
    action: "log"
    tags: ["custom", "bot", "scanner"]
```

### Tips for Good Rules

- **`action: log` is not an observation mode today** — it writes one `debug!`
  line, contributes no score and produces no audit-log row. See
  [`action: log` is silent](#action-log-is-silent). Until that changes, "log
  first" has to mean replaying traffic against the rule offline, not shipping
  it as `log` and watching.
- **Prefer `severity` over `action` to soften a rule.** A `warning` (3) rule
  needs a second hit to reach the inbound threshold of 5, which is the
  gradient CRS is built on; `critical` (5) is an unconditional block dressed
  up as a score.
- **Name the narrowest surface.** `all` walks every header value and every
  cookie value. Almost every false positive found in the audit came from a
  pattern that was fine on `args+body` and catastrophic on `all`.
- **Be specific with anchors** — use `^` and `$` in regexes to prevent partial matches.
- **Use non-capturing groups** — `(?:...)` instead of `(...)` for clarity.
- **Add comments** — YAML comments (`#`) are your future self's best friend.
- **Test your regex** — use `python3 -c "import re; re.compile('your_pattern')"`.
- **Set an appropriate paranoia level** — if a rule might match legitimate traffic,
  set paranoia to 2 or 3 rather than blocking at paranoia 1.

---

## Updating Rules

Rules are synced from upstream sources using `tools/sync.py`.

### Install dependencies

```bash
pip install -r tools/requirements.txt
```

### Check for updates

```bash
python tools/sync.py --check
```

### Sync OWASP CRS to a specific release tag

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --tag v4.10.0
```

### Sync to the latest main branch

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/
```

### Preview changes without writing files

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --dry-run
```

### Configuration

`sync-config.yaml` (in this directory) defines upstream sources and defaults.
You can override any config value via CLI flags. Supported flags:

| Flag          | Description                                  |
|---------------|----------------------------------------------|
| `--source`    | Source name (e.g. `owasp-crs`)               |
| `--output`    | Output directory                             |
| `--tag`       | Git tag to checkout (e.g. `v4.10.0`)         |
| `--branch`    | Git branch (default: `main`)                 |
| `--dry-run`   | Preview changes without writing              |
| `--check`     | Only report if updates are available         |
| `--config`    | Path to alternate config file                |
| `--temp-dir`  | Temp directory for cloning (default: `/tmp/prx-waf-sync/`) |

---

## Validation

Run `tools/validate.py` to check rule files for correctness before deploying.

### Validate all rule directories

```bash
python tools/validate.py rules/
```

### Validate a specific directory

```bash
python tools/validate.py rules/custom/
python tools/validate.py rules/owasp-crs/
python tools/validate.py rules/cve-patches/
```

### Validate a single file

```bash
python tools/validate.py rules/custom/myapp.yaml
```

### What the validator checks

- Required fields are present (`id`, `name`, `severity`, `field`, `operator`, `value`, `action`)
- No duplicate rule IDs across all loaded files
- Severity values are valid
- Paranoia levels are in range 1–4
- Action values are recognized
- Regexes compile correctly (PCRE-only patterns are flagged as warnings)
- Numeric operators are not used with string values

### Sample output

```
======================================================================
  prx-waf YAML Rule Validator
======================================================================

  ✓ owasp-crs/sqli.yaml                    87 rules
  ✓ owasp-crs/xss.yaml                     41 rules
  ✓ custom/myapp.yaml                       3 rules

----------------------------------------------------------------------
  Files:    3
  Rules:    131
  Errors:   0
  Warnings: 0
----------------------------------------------------------------------
  ✓ All files valid!
```

---

## Statistics

Two different numbers, and conflating them is how this table used to claim
"558 rules" for a WAF that enforces 285.

**Declared** is what is written in the YAML. **Compiled** is what the loader
turned into an enforceable matcher; the difference is rejected at startup with
a reason (`LoadSummary`, reported at `WARN`). **Enforced** is what the running
proxy evaluates — which is `owasp-crs/` and nothing else.

Measured by running the real loader (`OWASPCheck::from_directory`) over each
directory; reproduced by `rule_directory_load_status_is_pinned` in
`crates/waf-engine/src/checks/owasp.rs`.

| Directory        | Files | Declared | Compiled | Enforced by the proxy |
|------------------|-------|----------|----------|-----------------------|
| `owasp-crs/`     | 24    | 288      | 285      | **285** (226 request + 59 response) |
| `advanced/`      | 6     | 77       | 75       | 0 |
| `owasp-api/`     | 5     | 64       | 61       | 0 |
| `modsecurity/`   | 4     | 46       | 40       | 0 |
| `cve-patches/`   | 6     | 39       | 39       | 0 |
| `bot-detection/` | 3     | 42       | 42       | 0 |
| `custom/`        | 1     | 7        | 7        | 0 |
| **Total**        | 49    | 563      | 549      | **285** |

---

## Audit: why the other directories are off

All 275 unloaded rules were audited against the real loader and against a
benign-traffic corpus at the shipped defaults (paranoia 1, anomaly scoring on,
`critical` = 5 against an inbound threshold of 5 — so **one `critical` rule
match blocks the request on its own**).

The measured false-positive rate is the decisive number. Loading each
directory on its own and replaying 52 ordinary business requests (browser page
views, REST/JSON APIs, form posts, uploads, GraphQL, common API-client
user-agents, requests carrying `X-Forwarded-For` from an internal load
balancer):

| Directory        | Benign requests blocked | One-shot blockers (`block` + `critical` + PL1) |
|------------------|-------------------------|------------------------------------------------|
| `owasp-crs/`     | 5 / 52 (pre-existing)   | — |
| `advanced/`      | **7 / 52**              | 70 of 77 |
| `owasp-api/`     | **3 / 52**              | 21 of 64 |
| `cve-patches/`   | 0 / 52                  | 26 of 43 |
| `bot-detection/` | 0 / 52                  | 7 of 42 |
| `modsecurity/`   | 0 / 52                  | 7 of 46 |
| `custom/`        | 0 / 52                  | 1 of 7 |

A `0 / 52` is not a clean bill of health: 104 of the 275 rules are
`action: log`, which contributes no score and therefore cannot appear as a
block (see [`action: log` is silent](#action-log-is-silent) below).

### Confirmed against a running WAF

The table above comes from driving `OWASPCheck` directly. The same conclusion
was reproduced end to end — real binary, enforcing (`log_only_mode = false`),
Postgres, an `albedo` origin, and 40 requests sent with `curl` — by copying
`advanced/*.yaml` into the loaded directory, which is precisely what "just
point the loader at them" amounts to:

| | rules active | benign requests blocked | log4shell control |
|---|---|---|---|
| shipped (`owasp-crs/` only)     | 285 | 3 / 40  | 403 |
| `owasp-crs/` + `advanced/`      | 360 | **10 / 40** | 403 |

The seven newly blocked requests were: all four carrying an `X-Forwarded-For`
with a private address, a request whose only unusual feature was a `_ga`
analytics cookie (`ADV-SSRF-015` reads a 10-digit timestamp as a
decimal-encoded IP), a CMS saving a Jinja template, and a crash report
containing a Java stack trace.

The three the shipped set already blocks are pre-existing CRS behaviour, not
something these directories caused: an ops form posting
`redis://10.0.0.5:6379` (`CRS-931100`, RFI), a crash report naming
`org.springframework…`, and a rich-text field holding an XHTML doctype. They
are recorded here because a false-positive number is only meaningful against a
baseline.

### Per-directory verdict

| Directory | Verdict | Why |
|---|---|---|
| `advanced/` | **do not load** | `ADV-SSRF-001/002/003/004` are `field: all` + `critical` + PL1, and `all` includes **every request header value**. Any request carrying `X-Forwarded-For: …, 10.0.1.7` — i.e. every request behind an internal load balancer, which is this product's normal deployment — is blocked by a single rule. Measured: 4/4 such requests 403. `ssti.yaml` blocks ordinary template syntax (`{% block content %}`, `{{ settings.theme }}`), so any CMS or rich-text feature breaks. `prototype-pollution.yaml` and the back half of `xxe.yaml` are genuinely good; the rest is not. |
| `owasp-api/` | **do not load** | `API-MASS-001/002/010` block on `"role":"admin"`, `"is_admin":true` and `role`+`is_admin` appearing in the same body — i.e. every admin panel, every signup form that echoes the user object back, and every OpenAI-compatible request (`{"role":"system"}`). `broken-auth.yaml`'s JWT-attack rules are sound; the rate-abuse file cannot work at all (rate limiting is stateful, this check is not — see `crates/waf-engine/src/checks/cc.rs`). |
| `modsecurity/` | **do not load** | 16 of 46 duplicate something already enforced: CRS rules (`DOS-001`→`CRS-920160`, `DOS-006`→`CRS-911100`, `RESP-002`→`CRS-953120`, `RESP-004`→`CRS-950130`, `RESP-010`→`CRS-953100`) or a real subsystem (`sensitive.rs`, `cc.rs`, `ip_feed.rs`, `scanner.rs`). `data-leakage.yaml`'s 12 rules are named "… in response" but use `field: body`, which is the **request** body — the phase is inverted. `MODSEC-IPREP-004` is `critical` on a bare `canvas` substring, which blocks the Canvas LMS mobile app. |
| `cve-patches/` | **mostly do not load** | `2022-spring4shell.yaml` is the one file worth enabling as-is (CRS covers it only at PL2). Against that: `CVE-2025-NEXT-010` is `field: method` / `^PUT$` — every REST update; `CVE-2025-NEXT-004` matches `WebKit/…Safari|iPhone|iPad`, i.e. most browsers on earth; `CVE-2023-MOVEIT-003` fires on the PHP standard function `move_uploaded_file`; several rules are structurally dead (see below). |
| `bot-detection/` | **do not load** | `BOT-CRAWL-009` scores `AhrefsBot`, `SemrushBot`, `Sogou` and `YandexBot`, all four of which are on the engine's own good-bot allowlist (`crates/waf-engine/src/checks/bot.rs`) — and that allowlist does not protect them, because a `None` from `BotCheck` does not short-circuit the pipeline. ~20 of 42 duplicate `bot.rs` / `scanner.rs` more weakly. Scraping and credential stuffing are volumetric; `cc.rs` is the mechanism that can actually see them. |
| `custom/` | **template only, by design** | `example.yaml` is an annotated example for a hypothetical shop. It has no `enabled` key, so loading the directory would enforce the example on real traffic (`CUSTOM-APP-002` is `critical` on `/assets/*.sh`). The supported way to add your own rules is the custom-rules engine behind `POST /api/custom-rules` (`crates/waf-engine/src/rules/engine.rs`), which is a different format and a different code path. |

### Failure modes worth knowing before writing any rule

These bit the audited rules repeatedly. Each is verified against the engine, not inferred.

* **`field: headers` matches the name and the value separately**, never
  `Name: value` (`crates/waf-engine/src/checks/owasp.rs:1033`:
  `ctx.headers.iter().any(|(name, value)| f(name) || f(value))`). Any pattern
  containing a literal `Content-Range:` / `X-Forwarded-For:` can never match.
* **`field: cookies` yields cookie *values* only**, not names
  (`owasp.rs:1034`). A pattern containing `SVPNCOOKIE=` never matches.
* **`path`, `query` and `body` are already percent-decoded** and `+` is already
  a space. A pattern written against `%ADd+allow_url_include` never matches on
  those surfaces; header and cookie values are the undecoded ones.
* **`field: all` walks every request header value and every cookie value.**
  Reach for the narrowest surface list instead — see
  [Composite fields](#composite-fields).
* **`severity: critical` at paranoia 1 with `action: block` is an
  unconditional block**, because `critical` = 5 and the inbound threshold is 5.
  It is not "a strong signal that contributes to a score"; it is a 403 on the
  first match.

### `action: log` is silent

`RuleAction::Log` writes one `debug!` line and returns
(`crates/waf-engine/src/checks/owasp.rs:3593-3598`). It contributes no score,
and — because the audit log is built from the scoring contributions
(`record_audit`, `owasp.rs:3621`) — it produces **no audit-log record and no
`security_events` row**. At the default log level it produces nothing at all.

So the advice under [Tips for Good Rules](#tips-for-good-rules) — "start with
`action: log`, monitor before blocking" — does not currently work for
YAML rules. Nothing takes that branch today: all 288 shipped `owasp-crs/`
rules are `action: block`. Anyone enabling one of the audited directories in
"observe mode" would be observing silence, which is why 104 `action: log`
rules across those directories have never produced a single false-positive
report. Pinned by `log_action_contributes_no_score_and_no_audit_record`.

---

## Licensing

| Component              | License      | Copyright                          |
|------------------------|--------------|------------------------------------|
| OWASP CRS rules        | Apache-2.0   | OWASP CRS project contributors     |
| ModSecurity rules      | Apache-2.0   | prx-waf project                    |
| CVE patch rules        | Apache-2.0   | prx-waf project                    |
| Custom example rules   | Apache-2.0   | prx-waf project                    |
| Tooling (tools/*.py)   | Apache-2.0   | prx-waf project                    |

OWASP CRS is distributed under the Apache License, Version 2.0.
See: https://github.com/coreruleset/coreruleset/blob/main/LICENSE

prx-waf rules and tooling are distributed under the Apache License,
Version 2.0. See the LICENSE file in the repository root.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

### Adding or modifying rules

1. **Pick the right directory:**
   - `owasp-crs/` — do not edit directly; re-run `sync.py` to regenerate.
   - `modsecurity/` — hand-crafted rules for threat categories not in CRS.
   - `cve-patches/` — one file per CVE year-group; add new CVEs to the current year file.
   - `custom/` — application-specific overrides.

2. **Use the correct ID namespace:**

   | Directory      | ID Prefix                        |
   |----------------|----------------------------------|
   | `owasp-crs/`   | `CRS-<crs_number>`               |
   | `modsecurity/` | `MODSEC-<CATEGORY>-<NNN>`        |
   | `cve-patches/` | `CVE-<YEAR>-<SHORT>-<NNN>`       |
   | `custom/`      | `CUSTOM-<CATEGORY>-<NNN>`        |

3. **Validate before submitting:**
   ```bash
   python tools/validate.py rules/
   ```

4. **Do not introduce false positives** — test new rules against real traffic
   logs with `action: log` before switching to `action: block`.

5. **Document your rule** — use inline YAML comments (`#`) to explain
   the threat, the pattern rationale, and any known limitations.

6. **Reference sources** — include a `reference:` URL linking to the
   relevant CVE, OWASP article, or research paper.

### Submitting changes

- Open a pull request with a clear description of what the rule detects.
- Include before/after output from `validate.py`.
- For CVE patches, include a link to the NVD entry.

### Reporting false positives

If a rule incorrectly blocks legitimate traffic:
1. Identify the rule ID from the WAF log.
2. Open an issue with the rule ID, the blocked request (sanitized), and the
   application context.
3. Consider raising the rule's `paranoia` level as an interim mitigation
   while a fix is prepared.
