# Custom Rules

> ## NOT LOADED — this directory is documentation, not configuration
>
> The running proxy loads exactly one rule directory, `rules/owasp-crs/`, from a
> hardcoded path (`crates/waf-engine/src/checks/owasp.rs:53`). **A YAML file
> you drop here will never be evaluated**, and there is no setting that changes
> that. `example.yaml` is an annotated illustration of the rule schema for a
> hypothetical shop; it has no `enabled` key, so if the directory ever were
> loaded, those seven example rules would be enforced on your traffic
> (`CUSTOM-APP-002` is `critical` on any `.sh` under `/assets/`, and
> `CUSTOM-APP-003` says "Log access to…" in its name while carrying
> `action: block`).
>
> **The supported way to add your own rules is the custom-rules engine**
> (`crates/waf-engine/src/rules/engine.rs`), which is a different format on a
> different code path: conditions are stored in Postgres, combined with AND/OR,
> matched with 13 operators including `cidr_match` and the geographic fields,
> optionally gated by a Rhai script, scoped per host, and given a priority and
> an `enabled` flag. Create them over the admin API and they take effect
> immediately and replicate across the cluster:
>
> ```bash
> curl -X POST http://localhost:16827/api/custom-rules \
>   -H 'Content-Type: application/json' \
>   -d '{
>         "name": "Block the internal admin API from outside",
>         "enabled": true,
>         "priority": 100,
>         "conditions": [
>           {"field": "path", "operator": "regex", "value": "^/internal/"}
>         ],
>         "action": "block"
>       }'
> ```
>
> `GET /api/custom-rules` lists them, `DELETE /api/custom-rules/{id}` removes
> one. Invalid regexes are rejected when the rule is loaded, not at request
> time.
>
> Keep reading below for the YAML schema — it is accurate for
> `rules/owasp-crs/`, and it is what `tools/validate.py` checks — but do not
> expect a file in this directory to do anything.

## When to Write Custom Rules

- Application-specific paths and endpoints
- Business logic protection
- Proprietary API formats
- Tenant-specific blocklists

## Rule Schema

```yaml
version: "1.0"
description: "Short description of the ruleset"
rules:
  - id: "CUSTOM-CATEGORY-NNN"   # Unique string ID (REQUIRED)
    name: "Human readable description"  # Short name (REQUIRED)
    category: "your-category"   # Free-form category tag (REQUIRED)
    severity: "critical"        # critical | high | medium | low (REQUIRED)
    paranoia: 1                 # 1-4 paranoia level (optional, default 1)
    field: "all"                # See Field reference below (REQUIRED)
    operator: "regex"           # See Operator reference below (REQUIRED)
    value: "pattern"            # Pattern or value (REQUIRED)
    action: "block"             # block | log | pass (REQUIRED)
    tags: ["custom", "tag"]     # Optional string array
    reference: "https://..."    # Optional CVE/reference URL
```

## Field Reference

| Field | Description |
|-------|-------------|
| `path` | Request URI path |
| `query` | Query string arguments |
| `body` | Request body |
| `headers` | All request headers |
| `user_agent` | User-Agent header only |
| `cookies` | Request cookies |
| `method` | HTTP method |
| `content_type` | Content-Type header |
| `content_length` | Content-Length value (numeric) |
| `path_length` | URI path length (numeric) |
| `query_arg_count` | Number of query parameters (numeric) |
| `all` | All of the above |

## Operator Reference

| Operator | Description |
|----------|-------------|
| `regex` | Match against regular expression |
| `contains` | String contains value |
| `not_in` | Value not in list |
| `gt` | Greater than (numeric) |
| `lt` | Less than (numeric) |
| `detect_sqli` | SQL injection detection via libinjection |
| `detect_xss` | XSS detection via libinjection |
| `pm_from_file` | Phrase match from external list file |
| `contains_any` | Phrase match from an inline phrase set (`@pm`) |
| `starts_with` / `ends_with` | Literal prefix / suffix match |

## Naming Convention

Use the `CUSTOM-` prefix for all custom rule IDs to avoid conflicts with
built-in rule sets:

```
CUSTOM-<CATEGORY>-<NNN>

Examples:
  CUSTOM-API-001
  CUSTOM-APP-001
  CUSTOM-BOT-001
```

## Paranoia Levels

| Level | Meaning |
|-------|---------|
| 1 | Default – high confidence, low false positive rate |
| 2 | Moderate – increased protection, minor false positive risk |
| 3 | High – aggressive detection, requires tuning |
| 4 | Maximum – extreme detection, expect false positives |

## Validation

Run before deploying:

```bash
python tools/validate.py rules/custom/
```

## Example

See [example.yaml](example.yaml) for a complete working example.

## License

Custom rules you write are yours. The example rules in this directory
are provided under Apache License 2.0.
