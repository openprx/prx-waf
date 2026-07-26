# IPv4-mapped Address Normalization

**This is a breaking change.** If any prx-waf listener is bound to the IPv6
wildcard `[::]`, read this before upgrading. If every listener is `0.0.0.0`
(the shipped default), nothing about your deployment changes and you can skip
to [What still is not normalized](#5-what-still-is-not-normalized) for
context.

---

## 1. What changed

prx-waf now folds IPv4-mapped IPv6 client addresses (`::ffff:a.b.c.d`) down to
plain IPv4 (`a.b.c.d`) at the point where an address enters the process. Every
IP decision downstream — blocklists, allowlists, threat-intel feeds, CrowdSec,
`trusted_proxies`, GeoIP, rate-limit buckets — sees the plain IPv4 form.

Genuine IPv6 addresses are untouched. So is the deprecated IPv4-*compatible*
form `::a.b.c.d` (RFC 4291 §2.5.5.1), which a socket never produces and which
is treated as the suspicious input it is rather than silently reinterpreted.

## 2. Why

A socket bound to `[::]` accepts IPv4 connections too on any kernel with
`net.ipv6.bindv6only = 0` — the Linux default — and reports those peers in
IPv4-mapped form. Nothing folds the two spellings together on its own:

```
Ipv4Net("203.0.113.0/24").contains(::ffff:203.0.113.9)  ==  false
```

Cross-family containment is never true, in either direction. Before this
change, that single fact broke every IP adjudication in two opposite ways the
moment a listener was switched to `[::]`:

| Direction | Subsystems | Consequence |
|---|---|---|
| **fail-open** | IP blacklist, threat-intel feeds, CrowdSec `Ip` and `Range` decisions, community blocklist | A banned IPv4 attacker was **admitted**. This is a security bypass. |
| **fail-closed** | admin IP allowlist, IP whitelist, `trusted_proxies`, GeoIP `AllowOnly` | A legitimate IPv4 operator or client was **rejected**. |

The fail-closed direction was visible — an operator locked out of the admin API
notices within a minute and works around it by writing `::ffff:x.x.x.x` in the
allowlist. The fail-open direction is silent: a blocklist that has quietly
stopped matching looks exactly like a blocklist with nothing to match.

## 3. What you must do before upgrading

Only if a listener is bound to `[::]`.

1. **Rewrite every IP/CIDR rule spelled in mapped form to plain IPv4.** This
   covers `[security] admin_ip_allowlist`, `[proxy] trusted_proxies`, and the
   per-host IP blacklist / whitelist entries stored in the database (the admin
   UI's IP rules).

   | Old (dead after upgrade) | New |
   |---|---|
   | `::ffff:127.0.0.1` | `127.0.0.1` |
   | `::ffff:10.0.0.0/104` | `10.0.0.0/8` |
   | `::ffff:203.0.113.0/120` | `203.0.113.0/24` |

   A mapped `/N` prefix converts to `/(N-96)`, because the mapped block is
   `::ffff:0:0/96`.

2. **Start the daemon and read the startup log.** Nothing is rewritten for you;
   prx-waf names each offending entry instead:

   ```
   WARN IPv4-mapped entries in [security] admin_ip_allowlist are now DEAD and
        will never match: ::ffff:127.0.0.1 (use 127.0.0.1). ...
   WARN IP rule '::ffff:10.0.0.1' is written in IPv4-mapped IPv6 form and will
        never match: client addresses are normalized to plain IPv4 before
        matching. Rewrite it as '10.0.0.1'.
   ```

   The first line comes from the config-file scan at startup; the second from
   the rule loader, and it also fires on hot-reload, so database-stored rules
   are covered as they load.

   A `[::]` bind additionally logs one INFO line naming the affected listeners
   and restating the rule. Its absence means no listener can produce a mapped
   address, and none of this applies to you.

3. **Do not skip the fail-open direction.** If you previously wrote
   `::ffff:x.x.x.x` into an allowlist and left your *blacklist* in plain IPv4,
   your blacklist was not working. Check whether anything you meant to block
   has been getting through.

## 4. Where the fold happens

Exactly one point per ingress plane, and nowhere else:

| Plane | Normalization point |
|---|---|
| HTTP/1.1 + HTTP/2 data plane | `gateway::proxy::WafProxy::extract_client_ip` — both the TCP peer and a trusted right-most `X-Forwarded-For` entry |
| HTTP/3 data plane | `gateway::http3::handle_h3_request` — the QUIC peer (H3 has no XFF path) |
| Management API | `waf_api::security::request_client_ip` — the axum `ConnectInfo` peer |

The admin audit-log middleware (`waf_api::audit`) folds the same peer before
writing `audit_log.ip_addr`, so an audit row and the allowlist decision taken on
the same request name the client identically.

The helper is `waf_common::net::canonicalize_client_ip`. Consumers deliberately
do **not** fold: normalizing at each of a dozen comparison sites is what
produced the original bug, where the decision was made once for the admin
allowlist and silently inherited by the blocklist, the feeds and CrowdSec —
same mechanism, opposite consequence, never re-examined.

If you add a producer of a client address, fold it there and extend the table.
If you add a consumer, the address you receive is already canonical.

## 5. What still is not normalized

Normalization applies to addresses entering *now*. It says nothing about
addresses that were recorded earlier or that arrive from somewhere other than a
client socket:

- **Historical rows.** `security_events.client_ip`, `attack_logs.client_ip`,
  `audit_log.ip_addr`, `semantic_observations.client_ip` and
  `crowdsec_events.client_ip` keep whatever string was written when the row was
  created. A deployment that ran on `[::]` before this change has mapped-form
  strings in those tables forever. Log filters and the "top IPs" panel compare
  and `GROUP BY` on the raw string, so one attacker can still appear as two
  rows split across the upgrade boundary. No migration is applied; normalizing
  historical evidence in place would rewrite the record of what was actually
  observed.
- **CrowdSec LAPI decisions.** Decision values are parsed from what the LAPI
  sends. If a CrowdSec instance emits a mapped-form value, it lands in the
  cache in that form and — since client addresses are now canonical — will not
  match. In practice CrowdSec normalizes its own decisions, but prx-waf does
  not verify this.
- **Threat-intel feed entries and the community blocklist.** Same shape:
  external lists are loaded as supplied.
- **Cluster-synced rules.** IP rules replicated from a peer arrive as strings
  and are subject to the same load-time WARN as local ones, but a peer running
  an older build will keep re-publishing mapped entries until it is upgraded.
- **`waf_api::auth`'s login-throttle bucket** keys on the raw axum peer
  address rather than the canonical one, so on a `[::]` listener an IPv4 client
  and its mapped spelling would occupy separate buckets. Contained: it is a
  counter, not an adjudication, and both spellings cannot arrive on the same
  connection.
- **Rate-limit granularity is unchanged.** Every per-IP limiter still keys on
  the full address, which for IPv6 means /128 — a client with a routed /64
  still controls 2⁶⁴ distinct buckets. That is a separate defect and is not
  addressed here.
