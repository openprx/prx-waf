# Advanced Attack Rules

This directory contains advanced WAF rules for sophisticated attack patterns not fully covered by OWASP CRS or ModSecurity defaults.

## Rule Files

| File | Coverage |
|------|----------|
| `ssrf.yaml` | Server-Side Request Forgery — comprehensive beyond CRS |
| `deserialization.yaml` | Java, PHP, Python, .NET, Ruby deserialization attacks |
| `xxe.yaml` | XML External Entity attacks — DOCTYPE, entities, XInclude |
| `ssti.yaml` | Server-Side Template Injection — Jinja2, Twig, Freemarker, Velocity, etc. |
| `prototype-pollution.yaml` | JavaScript prototype pollution via JSON |
| `webshell-upload.yaml` | Webshell upload detection — PHP, JSP, ASP, polyglots |

## ID Namespace

All rules use the `ADV-` prefix.

- `ADV-SSRF-*` — SSRF attack patterns
- `ADV-DSER-*` — Deserialization attack patterns
- `ADV-XXE-*`  — XML External Entity attacks
- `ADV-SSTI-*` — Server-side template injection
- `ADV-PROTO-*` — Prototype pollution
- `ADV-SHELL-*` — Webshell upload detection

## Severity Guide

Rules in this directory are generally `critical` or `high` severity with paranoia 1-2, as they target well-known, exploitable attack classes with low false-positive rates.

## References

- https://portswigger.net/web-security
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/
