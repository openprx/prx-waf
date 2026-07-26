# OWASP Core Rule Set (CRS)

Converted from OWASP CRS v4.25.0-dev.

Source: https://github.com/coreruleset/coreruleset
License: Apache License 2.0
Converted: 2025

## Rule Files

| File | CRS Range | Category | Description |
|------|-----------|----------|-------------|
| `method-enforcement.yaml` | 911xxx | Protocol | HTTP method allowlist |
| `scanner-detection.yaml` | 913xxx | Scanner | Security scanner UA detection |
| `protocol-enforcement.yaml` | 920xxx | Protocol | HTTP protocol compliance |
| `protocol-attack.yaml` | 921xxx | Protocol | HTTP request smuggling, CRLF |
| `multipart-attack.yaml` | 922xxx | Protocol | Multipart boundary attacks |
| `lfi.yaml` | 930xxx | LFI | Local file inclusion / path traversal |
| `rfi.yaml` | 931xxx | RFI | Remote file inclusion |
| `rce.yaml` | 932xxx | RCE | Remote code execution (shell) |
| `php-injection.yaml` | 933xxx | PHP | PHP injection attacks |
| `generic-attack.yaml` | 934xxx | Generic | Node.js, SSI, HTTP splitting |
| `xss.yaml` | 941xxx | XSS | Cross-site scripting |
| `sqli.yaml` | 942xxx | SQLi | SQL injection |
| `session-fixation.yaml` | 943xxx | Session | Session fixation |
| `java-injection.yaml` | 944xxx | Java | Java deserialization, EL injection |
| `data-leakage.yaml` | 950xxx | Response | Generic data leakage |
| `data-leakage-sql.yaml` | 951xxx | Response | SQL error disclosure |
| `data-leakage-java.yaml` | 952xxx | Response | Java error disclosure |
| `data-leakage-php.yaml` | 953xxx | Response | PHP error disclosure |
| `data-leakage-iis.yaml` | 954xxx | Response | IIS error disclosure |
| `web-shells.yaml` | 955xxx | Response | Web shell detection |
| `data-leakage-ruby.yaml` | 956xxx | Response | Ruby error disclosure |

The 950–956 files are **response-phase** (`ModSecurity` `phase:4`): every rule in
them reads `response_body` or `response_status`. `OWASPCheck` partitions on that
at load time and evaluates them through `ResponseCheck`, against the outbound
anomaly score and `owasp.outbound_anomaly_score_threshold` (upstream default
**4**, deliberately not the inbound 5 — see CRS `959100`).

An earlier converter generation wrote the same rules a second time as
`response-*.yaml` with `CRS-RESP-` ids. Those files were removed: loading both
made every duplicated rule contribute its severity to the outbound score twice.

## Data Files

The `data/` directory contains wordlists used by `pm_from_file` rules:

| File | Used By | Contents |
|------|---------|----------|
| `scanners-user-agents.data` | 913100 | Known scanner User-Agents |
| `lfi-os-files.data` | 930120 | OS-specific file paths |
| `restricted-files.data` | 930130 | Restricted file extensions |
| `restricted-upload.data` | 933110 | Dangerous upload extensions |
| `unix-shell.data` | 932100 | Unix shell commands |
| `unix-shell-builtins.data` | 932150 | Unix shell builtins |
| `unix-shell-aliases.data` | 932160 | Unix shell aliases |
| `windows-powershell-commands.data` | 932200 | PowerShell commands |
| `php-function-names-933150.data` | 933150 | Dangerous PHP functions |
| `php-errors.data` | 953100 | PHP error strings |
| `php-variables.data` | 933120 | PHP superglobal variables |
| `sql-errors.data` | 951100 | SQL error strings |
| `java-classes.data` | 944110 | Dangerous Java classes |
| `asp-dotnet-errors.data` | 954110 | ASP.NET error strings |
| `iis-errors.data` | 954120 | IIS error strings |
| `ruby-errors.data` | 956100 | Ruby error strings |
| `web-shells-php.data` | 955100 | PHP web shell patterns |
| `web-shells-asp.data` | 955110 | ASP web shell patterns |
| `ssrf.data` | 934100 | SSRF target patterns |
| `ssrf-no-scheme.data` | 934110 | SSRF no-scheme patterns |
| `ai-critical-artifacts.data` | 934150 | AI/ML sensitive artifacts |

## Chained Rules (`chain:`)

A `ModSecurity` `SecRule ... "chain"` is one rule whose conditions must **all**
hold. The YAML mirrors that: the head condition stays at the top level and the
remaining conditions go in an optional `chain:` list. A rule without `chain:` is
an ordinary single-condition rule and needs no change.

```yaml
- id: CRS-944110
  paranoia: 1
  field: query+body+cookies+headers   # head condition
  operator: regex
  value: (?:runtime|processbuilder)
  chain:                              # every link must also hold
    - field: matched_value
      operator: regex
      value: (?i)(?:unmarshaller|base64data|java\.)
  action: block
```

Each link takes the same `field` / `operator` / `value` keys as the head, plus:

| Key | Meaning |
|-----|---------|
| `negate: true` | `!@op` — the condition holds for a value the matcher rejects |
| `capture: true` | bind this regex's groups to `tx:0`…`tx:N` for later conditions (regex only; `capture` is also valid on the head) |

Two pseudo-fields are available to a chain link only:

| `field` | `ModSecurity` | Meaning |
|---------|---------------|---------|
| `matched_value` | `MATCHED_VAR` / `MATCHED_VARS` | the values the previous condition matched, in the form it matched them (URL-decoded when the match was made on a decoded form) |
| `tx:N` | `TX:N` | capture group `N` of the last capturing condition (`tx:0` is the whole match) |

A comparison operand (`equals`, `contains`, `starts_with`, `ends_with`) may
expand `%{TX.N}` and `%{REQUEST_HEADERS.HOST}`. Any other macro is refused at
load time rather than compared as a literal.

`count_header_<name>` is a header **presence** test (`&REQUEST_HEADERS:<name>`),
valid only with `equals` against `'0'` or `'1'` — repeated headers are folded
into one entry, so no other count is reachable. Its inventory is smaller than
the readable one on purpose: the engine can read any header by name
(`header:<name>`), but turning a `&VAR` test into an enforced rule changes what
the rule set blocks, so a header is added to `COUNT_MAPPED_HEADERS` in
`rules/tools/modsec2yaml.py` only together with false-positive probes for the
rules it activates.

Evaluation short-circuits: the head is tested first with the ordinary
allocation-free path, and the chain runs only if it matched.

A chained CRS rule the converter cannot express faithfully is refused **whole**
— its `field` becomes an `unmapped_chained_*` marker that the engine rejects and
names in the startup `WARN`. Emitting only the first condition is never
conservative: it is always a broader rule than upstream (CRS-944110's first
condition alone blocks any request mentioning "runtime").

## Paranoia Levels

| Level | Description | False Positive Risk |
|-------|-------------|---------------------|
| 1 | Default | Very low |
| 2 | Recommended | Low |
| 3 | Aggressive | Moderate |
| 4 | Maximum | High |

Start with paranoia level 1 in production, increase gradually with tuning.

## Updating

To pull the latest CRS and re-convert:

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --tag v4.10.0
```

Or use a local clone:

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --local /tmp/owasp-crs
```

## License

OWASP CRS is distributed under Apache License 2.0.
Copyright (c) 2006-2020 Trustwave and contributors.
Copyright (c) 2021-2026 CRS project.
