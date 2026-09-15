- **The proxy runs on Pingora 0.9.0** (`pingora-core`, `pingora-proxy`,
  `pingora-http`, `pingora-timeout`, all from 0.8.1), and the workspace's own
  `nix` moved from 0.24 to 0.31 so that the tree carries one copy again.
  Nothing in the configuration changes. What an operator can observe does:
  Pingora 0.9 now refuses a request with two `Host` lines, or whose
  absolute-form target authority (HTTP/1.1) or `:authority` (h2) contradicts
  its `Host`, *before* the WAF's `request_filter` runs — with a bodiless 400,
  no `prxwaf_requests_total` row and no WAF log line. The WAF's own refusals
  of the same requests remain as the second layer, and the three E2E scripts
  that exercised them now pin which layer answers. Pingora 0.9 also strips
  hop-by-hop and `Connection`-nominated headers from upstream requests by
  default, which this proxy accepts: the smuggling detector reads the
  downstream headers before that point, and no upstream contract depended on
  `Connection`, `Keep-Alive`, `TE` or `Proxy-*` fields being relayed.
