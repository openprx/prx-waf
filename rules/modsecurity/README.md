> ## NOT LOADED — audited 2026-07-26
>
> The running proxy does not load this directory and never has; it reads only
> `rules/owasp-crs/` from a hardcoded path
> (`crates/waf-engine/src/checks/owasp.rs:53`). **Do not point the loader at
> it.** 46 rules declared, 40 compile. It blocked 0 of 52 benign requests —
> but 31 of the 46 are `action: log`, which contributes no score and cannot
> block, so that number understates the noise.
>
> Six do not compile: `MODSEC-LEAK-002` and `MODSEC-IPREP-010` use lookahead;
> `MODSEC-DOS-001/002/003/008` write `value: "10485760"` as a quoted string
> where `gt` requires a YAML integer.
>
> Findings, worst first:
>
> * **`data-leakage.yaml` has its phase inverted.** All 12 rules are named
>   "… in response" and all 12 use `field: body`, which is the **request**
>   body (`owasp.rs:745`). They inspect what the user uploaded, not what the
>   origin leaked. `MODSEC-LEAK-003/004` also duplicate the built-in
>   `SensitiveCheck` patterns (`crates/waf-engine/src/checks/sensitive.rs`).
> * **`dos-protection.yaml` re-implements, badly, a subsystem that exists.**
>   Rate limiting lives in `crates/waf-engine/src/checks/cc.rs` — a token
>   bucket keyed on `(host, client_ip)` with automatic banning, on by default.
>   A stateless per-request regex cannot see a rate. The one thing this file
>   could measure, body size, is already `CRS-920160` at `critical` (this
>   file's copy is `high`, and does not load).
> * **`ip-reputation.yaml` contains no IP field.** It matches user-agents and
>   headers the client controls. Real IP reputation is
>   `rules/ip_feed.rs` (Tor exits, ET Open, Spamhaus),
>   `community/blocklist.rs` and `crowdsec/`. `MODSEC-IPREP-004` is `critical`
>   on a bare `canvas` substring, which blocks the Canvas LMS mobile app.
> * **Three rules can never match**: `MODSEC-DOS-004`, `MODSEC-IPREP-008` and
>   `MODSEC-IPREP-009` all match a literal `Header-Name:`, but `field: headers`
>   hands the matcher the name and the value as two separate strings
>   (`owasp.rs:1033`).
> * **Duplicates already enforced by CRS**: `DOS-001`→`CRS-920160`,
>   `DOS-006`→`CRS-911100`, `IPREP-003`→`CRS-913100`, `RESP-002`→`CRS-953120`,
>   `RESP-004`→`CRS-950130`, `RESP-010`→`CRS-953100`. `RESP-004` is the same
>   rule as the `CRS-950130` / `CRS-RESP-950130` double-count already recorded
>   in `CHANGELOG.md`.
>
> Worth keeping if this directory is ever revisited: `MODSEC-RESP-005` (`.git`
> config exposure), `RESP-008` (Spring actuator), `RESP-009` (k8s Secret),
> `RESP-011`/`RESP-012` (Node/Python tracebacks) are genuine gaps in CRS
> coverage. `RESP-006` is too — but its `API_KEY=` branch fires on every
> Swagger page, and at `critical` in the response phase that is a blocked page.

# ModSecurity Community Rules

Hand-crafted prx-waf rules inspired by ModSecurity community best practices.
These rules cover threat categories not fully addressed by OWASP CRS.

## Rule Sets

| File | Description | Rules |
|------|-------------|-------|
| `ip-reputation.yaml` | Malicious bot/scanner/proxy detection | 10 |
| `dos-protection.yaml` | DoS and rate-limiting indicators | 12 |
| `data-leakage.yaml` | PII and credential leak detection | 12 |
| `response-checks.yaml` | Response inspection (web shells, error disclosure) | 12 |

## Coverage

- **IP Reputation**: Blocks known scanners (Nikto, SQLMap, Nmap, Metasploit),
  headless browsers, and spoofed X-Forwarded-For headers.

- **DoS Protection**: Detects oversized requests, abnormal argument counts,
  HTTP TRACE/DEBUG methods, XML bomb patterns.

- **Data Leakage**: Detects credit card numbers, SSNs, AWS keys, private SSH keys,
  database connection strings, JWT tokens, and Git tokens in responses.

- **Response Checks**: Detects PHP/ASP web shells, directory listings, `.env`
  file exposure, verbose stack traces, and Spring Boot actuator leaks.

## Source

Written by prx-waf project. Apache License 2.0.

## Updating

These rules are maintained manually. To add rules:

1. Copy the rule schema from `rules/custom/README.md`
2. Use IDs in the `MODSEC-<CATEGORY>-NNN` namespace
3. Run `python tools/validate.py rules/modsecurity/`

## Paranoia Levels

Rules in this directory use paranoia levels 1 (essential) and 2 (recommended).
Level 3+ rules are logged only, not blocked.
