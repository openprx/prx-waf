> ## NOT LOADED — audited 2026-07-26
>
> The running proxy does not load this directory and never has; it reads only
> `rules/owasp-crs/` from a hardcoded path
> (`crates/waf-engine/src/checks/owasp.rs:53`). **Do not point the loader at
> it.** 77 rules declared, 75 compile, and replaying 52 ordinary business
> requests through them blocked **7**.
>
> The two rules that do not compile are `ADV-SHELL-005` (`\0` is read as a
> backreference) and `ADV-SHELL-012` (`(?!/script>)` is lookahead); the Rust
> `regex` engine supports neither.
>
> **70 of the 77 are `action: block` + `severity: critical` + `paranoia: 1`,
> which with the shipped scoring means each one blocks on its own.** There is
> no severity gradient in this directory to tune.
>
> Measured hazards, worst first:
>
> * `ADV-SSRF-001/002/003/004` — `field: all` includes every request **header
>   value**, so a private IP anywhere in `X-Forwarded-For` is a 403. That is
>   every request behind an internal load balancer or a k8s ingress: the normal
>   deployment for this product. All four measured blocking, one benign request
>   each.
> * `ADV-SSRF-015` — the pattern reduces to "any 8-10 digit run followed by
>   `:`, `/`, or end of value". Unix timestamps and analytics cookies qualify.
> * `ADV-SSTI-002/004/007/008/009` — match template syntax itself
>   (`{% block content %}`, `{{ settings.theme }}`, `${openModal}`), so any CMS,
>   email-template editor or i18n catalogue breaks.
> * `ADV-DSER-003/004` — bare `org.springframework.…` and `java.lang.Runtime`
>   substrings, which every Sentry-style crash report carries.
> * `ADV-SHELL-011` — blocks `GET /files/installer.exe`, `/docs/install.sh` and
>   friends; the pattern describes downloads, not uploads.
>
> Worth keeping if this directory is ever revisited:
> `prototype-pollution.yaml` (9 of 10 measured clean and structurally
> specific) and the `SYSTEM "`-anchored half of `xxe.yaml`
> (`ADV-XXE-003/004/005/006/007/008/012/013`). `ADV-XXE-001/002/009/010` are
> not — `002` fires on every XHTML doctype.

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

Rules in this directory are generally `critical` or `high` severity with paranoia 1-2.

This used to claim "low false-positive rates". It was never measured, and it is
not true: 7 of 52 ordinary business requests are blocked, and 70 of the 77 rules
block on their own at the shipped defaults. See the audit note at the top of
this file.

## References

- https://portswigger.net/web-security
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/
