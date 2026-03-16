# OWASP API Security Top 10 (2023) Rules

This directory contains WAF rules aligned to the [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).

## Rule Files

| File | Coverage | Rules |
|------|----------|-------|
| `broken-auth.yaml` | API1:2023 Broken Object Level Authorization / API2:2023 Broken Authentication | JWT attacks, brute force, token leakage |
| `injection.yaml` | API8:2023 Security Misconfiguration / Injection | GraphQL, NoSQL, LDAP, XXE, SSRF via API |
| `mass-assignment.yaml` | API3:2023 Broken Object Property Level Authorization | Privilege escalation via mass assignment |
| `rate-abuse.yaml` | API4:2023 Unrestricted Resource Consumption | Rate abuse, bulk requests, GraphQL batching |
| `data-exposure.yaml` | API3:2023 + API5:2023 Broken Function Level Authorization | Sensitive data in params, debug responses |

## ID Namespace

All rules in this directory use the `API-` prefix.

- `API-AUTH-*` — Authentication and authorization attacks
- `API-INJ-*`  — Injection attacks via API
- `API-MASS-*` — Mass assignment / property pollution
- `API-RATE-*` — Rate and resource abuse
- `API-EXPO-*` — Data exposure patterns

## Paranoia Levels

- **1** — High-confidence, low false-positive (always enabled)
- **2** — Recommended for most deployments
- **3** — Aggressive; may need tuning
- **4** — Paranoid mode; expect false positives

## References

- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- https://portswigger.net/web-security/api-testing
