# Geographic rules are not YAML rules

There used to be a `country-blocklist.yaml` here. It could never have worked,
and it has been removed. This file records why, so nobody writes another one.

## Why a YAML rule cannot make a geographic decision

Four independent reasons, each on its own fatal:

1. **This directory is not loaded.** The engine reads exactly one rule
   directory, `rules/owasp-crs/`, from a hardcoded path
   (`crates/waf-engine/src/checks/owasp.rs:53`).
2. **`geo_iso` / `geo_isp` are not fields.** `Field::parse`
   (`crates/waf-engine/src/checks/owasp.rs:809-864`) has no geographic
   variant, so both rules were rejected as `UnsupportedField` when loaded
   experimentally — 2 declared, 0 compiled.
3. **`in` is not an operator.** The loader accepts `not_in`, not `in`
   (`owasp.rs:3067-3096`).
4. **The OWASP phase cannot see `ctx.geo`.** Its `RequestView` is built from
   the HTTP surfaces only; the resolved GeoIP record never reaches it.

## How to actually block by country

Through the **custom-rules engine**, which is a different subsystem with a
different storage format and its own admin API.

1. Enable GeoIP and fetch the databases:

```toml
[geoip]
enabled = true
ipv4_xdb_path = "data/ip2region_v4.xdb"
ipv6_xdb_path = "data/ip2region_v6.xdb"
cache_policy  = "full_memory"   # full_memory | vector_index | no_cache
```

```bash
prx-waf geoip download
```

2. Create the rule over the admin API:

```bash
curl -X POST http://localhost:16827/api/custom-rules \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "Block high-risk countries",
        "enabled": true,
        "priority": 100,
        "conditions": [
          {"field": "geo_iso", "operator": "in_list", "value": "KP,IR,SY"}
        ],
        "action": "block"
      }'
```

The supported condition fields are `geo_iso`, `geo_country`, `geo_province`,
`geo_city` and `geo_isp` (`crates/waf-engine/src/rules/engine.rs:36-47`), with
`in_list` / `not_in_list` / `cidr_match` among the operators
(`engine.rs:53-68`). Rules are stored in Postgres, take effect immediately, and
are broadcast to the rest of the cluster.

## Known gap

`GeoCheck` (`crates/waf-engine/src/checks/geo.rs`) is a second, fully
implemented geographic matcher with an `AllowOnly` fail-closed mode — and it
has no production wiring at all. `GeoCheck::load_rules` is called only from its
own `#[cfg(test)]` block, so the check runs on every request against an
permanently empty rule table. Use the custom-rules engine until that is
resolved either way.
