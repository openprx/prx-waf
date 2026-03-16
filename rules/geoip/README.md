# GeoIP Rules

Rules in this directory are evaluated against the GeoIP information resolved
from the client IP address on every request.

## Prerequisites

1. Enable GeoIP in your configuration:

```toml
[geoip]
enabled = true
ipv4_xdb_path = "data/ip2region_v4.xdb"
ipv6_xdb_path = "data/ip2region_v6.xdb"
cache_policy   = "full_memory"   # full_memory | vector_index | no_cache
```

2. The xdb files are downloaded automatically when you run `prx-waf geoip download`,
   or manually:

```bash
mkdir -p data/
curl -L -o data/ip2region_v4.xdb \
  "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb"
curl -L -o data/ip2region_v6.xdb \
  "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb"
```

## Supported rule fields

| `field`        | Matches                                     | Example value      |
|----------------|---------------------------------------------|--------------------|
| `geo_iso`      | ISO 3166-1 alpha-2 code (uppercase)         | `"CN"`, `"US"`     |
| `geo_country`  | Full country name                           | `"China"`          |
| `geo_province` | Province / state                            | `"Guangdong"`      |
| `geo_city`     | City                                        | `"Shenzhen"`       |
| `geo_isp`      | ISP / network operator                      | `"ChinaNet"`       |

These fields can be used in both YAML rules (via the `field` key) and in
custom Rhai scripted rules (e.g. `ctx.geo_iso == "CN"`).

## Example rules

### Block a list of countries by ISO code

```yaml
- id: "GEO-COUNTRY-001"
  name: "Block high-risk countries"
  category: "geo"
  severity: "high"
  paranoia: 1
  field: "geo_iso"
  operator: "in"
  value: ["KP", "IR", "SY"]
  action: "block"
  tags: ["geoip", "country-block"]
```

### Allow only specific countries (block all others)

Load this rule via the `GeoCheck::load_rules` API with `GeoRuleMode::AllowOnly`
to restrict access to an explicit allowlist.

### Log requests from a specific ISP

```yaml
- id: "GEO-ISP-001"
  name: "Log ChinaNet traffic"
  category: "geo"
  severity: "info"
  field: "geo_isp"
  operator: "contains"
  value: "ChinaNet"
  action: "log"
  tags: ["geoip", "isp"]
```

## Performance

ip2region uses a binary xdb format with three cache modes:

| Mode           | Memory (IPv4) | Memory (IPv6) | Query latency |
|----------------|---------------|---------------|---------------|
| `full_memory`  | ~20 MB        | ~200 MB       | ~120 ns       |
| `vector_index` | ~2 MB         | ~2 MB         | ~27 µs        |
| `no_cache`     | ~1 MB         | ~1 MB         | ~54 µs        |

`full_memory` is recommended for production deployments where memory is
available; it adds negligible per-request latency.
