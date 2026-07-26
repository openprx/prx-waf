> ## NOT LOADED — audited 2026-07-26
>
> The running proxy does not load this directory and never has; it reads only
> `rules/owasp-crs/` from a hardcoded path
> (`crates/waf-engine/src/checks/owasp.rs:53`). **Do not point the loader at
> it.** 64 rules declared, 61 compile, and replaying 52 ordinary business
> requests through them blocked **3**.
>
> `API-EXPO-011`, `API-INJ-007` and `API-RATE-010` do not compile (lookahead
> and backreferences, which the Rust `regex` engine does not support).
>
> Measured hazards, worst first:
>
> * `API-MASS-001/002/010` are `critical` + `paranoia: 1` + `block`, i.e. a 403
>   on first match, and they fire on the most ordinary API bodies there are:
>   `{"role":"admin"}` (every admin panel), `{"role":"system"}` (every
>   OpenAI-compatible request), and any body carrying `role` and `is_admin`
>   together — which is what you get when a client GETs a user object and PUTs
>   it back.
> * `API-INJ-004` matches `"$type"` (Json.NET) and `{"$gt": …}` (any Mongo-style
>   filter API). `API-INJ-009` matches every XHTML doctype. `API-INJ-010`
>   matches `&nbsp;http://…` in any HTML body.
> * `API-EXPO-008/009` are response-phase and `critical`, so they block the
>   origin's answer: `009` fires on `-----BEGIN CERTIFICATE-----`, which is a
>   public key, not a secret.
> * `rate-abuse.yaml` cannot work. Rate limiting is stateful and this check
>   sees one request at a time; `API-RATE-009/011` are structurally dead
>   because `field: headers` matches names and values separately, so a pattern
>   containing `Content-Range:` never matches.
> * `API-AUTH-008/009/010` claim to detect missing-authorization, brute force
>   and credential stuffing, but match only the request **path** or the shape
>   of a login body. They fire on every login.
>
> Worth keeping if this directory is ever revisited: the JWT-attack rules in
> `broken-auth.yaml` (`API-AUTH-001/002/004/013`) measured clean and are
> specific to real attacks — `alg:none`, empty-signature `Bearer`, embedded
> `jwk`. Note the directory has no object-level-authorization rule at all,
> despite the API1/API5 headings: a WAF cannot see whether the caller owns
> object 42, and the absence is correct.

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
