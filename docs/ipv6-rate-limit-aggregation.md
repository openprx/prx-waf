# IPv6 Rate-Limit Aggregation (/64)

**This changes rate-limit behaviour for IPv6 clients only.** If no prx-waf
listener is bound to `[::]` — the shipped default is `0.0.0.0` everywhere —
nothing about your deployment changes.

---

## 1. What changed

Every per-IP rate limiter now accounts IPv6 clients **per `/64` network**
instead of per address. IPv4 is unchanged: still per address, i.e. `/32`.

| Limiter | Where | IPv4 | IPv6 |
|---|---|---|---|
| CC protection (`cc_rps`, `cc_burst`, `cc_ban_threshold`) | `waf-engine/src/checks/cc.rs` | `/32` (unchanged) | `/64` |
| Management API throttle (`api_rate_limit_rps`) | `waf-api/src/security.rs` | `/32` (unchanged) | `/64` |
| Login brute-force throttle (fixed at 10 rps) | `waf-api/src/auth.rs` | `/32` (unchanged) | `/64` |

The unit of account is `waf_common::net::RateLimitKey`, and `/64` is the
constant `waf_common::net::IPV6_RATE_LIMIT_PREFIX`.

**Not changed:** the Lane 2 semantic canary bucket
(`waf-engine/src/engine.rs`, `dispatch_semantic`) still keys on the full
address. It is a rollout sampling key, not an accounting key — see
[§5](#5-what-is-deliberately-not-aggregated).

## 2. Why

A per-IP limiter is a map from *a client* to a token bucket. Over IPv4 an
address is a serviceable stand-in for a client. Over IPv6 it is not: the
standard residential and VPS allocation is a routed `/64`, so one client owns
2⁶⁴ addresses and can present a fresh one on every request, for free.

Keyed on the full address, a limiter facing such a client fails in two ways at
once:

1. **The limit never engages.** Each request creates a bucket, spends one token
   and abandons it. `violation_count` never advances past 1, so `CC-BAN` — and
   with it `cc_ban_threshold` / `cc_ban_duration_secs` — is unreachable. The
   login throttle is likewise unbounded.
2. **The limiter attacks its own users.** Both limiters cap their map
   (`MAX_ENTRIES = 100_000` for CC, `API_RATE_MAX_ENTRIES = 50_000` for the
   API) and, once over the cap, evict **oldest first**. A rotation flood adds
   one entry per request, so the entries it forces out are the ones belonging to
   steady, legitimate clients. Under exactly the attack the limiter exists to
   stop, it degrades into an eraser for everyone else's state.

Aggregating to `/64` makes the flood cost one bucket and one map entry, which is
what the limiter was designed around.

`/64` is not a tuned number: RFC 4291 §2.5.4 fixes the interface identifier of
every unicast address at the low 64 bits, so it is the smallest unit an IPv6
network is ever subdivided into. Aggregating at any longer prefix accounts a
fraction of one client, which is the same as not accounting at all. It matches
what large edge networks (Cloudflare, Fastly) do.

## 3. What this costs you

**Distinct hosts inside one `/64` share a quota.** A home LAN, an office
segment, a container host — all the devices behind one prefix now spend from one
bucket. This is the accepted trade: a limiter that cannot be evaded for free is
worth more than per-device precision.

If you serve many independent hosts from a single `/64`, raise `cc_rps` and
`cc_burst` for the affected host before upgrading. There is no way to size this
from the outside; it depends on how many real clients sit behind your busiest
prefix.

Two things this does **not** do:

- It does not merge different `/64`s. Adjacent prefixes, different `/48`s and
  different `/32`s all keep independent buckets.
- It does not touch IPv4. `203.0.113.9` and `203.0.113.10` are two buckets, as
  they always were, and no v4 bucket ever aliases a v6 one.

## 4. Why the prefix length is a constant and not a setting

It was considered and rejected. The only safe value is `/64`:

- Raising it (`/96`, `/128`) silently restores the unbounded bucket space this
  exists to close, with no error and no log line — the limiter simply stops
  working again.
- Lowering it (`/56`, `/48`) merges unrelated customers of the same ISP
  allocation into one quota. That is a self-inflicted denial of service, and the
  operator would learn about it from user complaints rather than from prx-waf.

Site-level aggregation (`/56`, `/48`) is a coherent feature, but it is
*customer-level accounting* with its own limits and its own operator-visible
semantics — not a prefix-length tweak on this one.

## 5. What is deliberately not aggregated

The Lane 2 semantic **canary bucket** still keys on the full client address.

The canary is not accounting. `rollout_bps` selects a fraction of traffic for
`enforce` while the semantic lane is otherwise `log_only`; it exists to bound the
blast radius of switching enforcement on. The realised enforce-share tracks the
configured fraction only in proportion to the number of *independent* keys
observed, so bucketing by `/64` collapses however many addresses a prefix
presents into a single coin flip — turning a "1 %" rollout into 0 % or 100 % of
that prefix's traffic. That is precisely the outcome the knob exists to prevent.

The error is asymmetric, too. An over-aggregated limiter costs a legitimate
client some quota. An over-aggregated canary blocks a whole subnet's traffic
during the phase where the operator has explicitly declared they do not yet
trust the detector.

There is also no evasion to close by aggregating it: landing outside the canary
yields `Log`, which is where all traffic sits in the shipped posture
(`rollout_bps = 0`) and where everything outside the experiment sits otherwise.
Lane 1, OWASP CRS, CC protection and the IP blocklists all run regardless, so
rotating out of a canary bucket gains an attacker nothing.

## 6. Interaction with IPv4-mapped normalization

See [IPv4-mapped Address Normalization](./ipv4-mapped-normalization.md) for the
`::ffff:a.b.c.d` fold that landed first.

Two notes specific to bucketing:

- `RateLimitKey::from_client_ip` folds a mapped address **before** masking, and
  does so even though the ingress boundary already folded it. This is the one
  deliberate exception to the "consumers do not normalize" invariant, because the
  failure is not symmetric: masking an unfolded `::ffff:a.b.c.d` to `/64` clears
  the embedded IPv4 address entirely, so *every* IPv4 client on a `[::]` listener
  would collapse into one `::/64` bucket and share one quota.
- The login throttle in `waf_api::auth::login` previously read the axum peer
  address directly and so sat outside the normalization boundary; it now goes
  through `waf_api::security::canonical_peer_ip`. On a `[::]` listener an IPv4
  client's plain and mapped spellings no longer occupy two brute-force budgets.
