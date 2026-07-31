- **A request whose authority contradicts its `Host` is refused with 400**, and
  counted as
  `prxwaf_budget_events_total{subsystem="request_headers",limit="contradicted_authority"}`.
  Reachable on h2, where a client may send both and neither `h2` nor Pingora
  compares them; not reachable on HTTP/1.1, whose request targets carry no
  authority. Picking a side would be the desync itself — this proxy would apply
  one site's policy to a request the origin resolves as another's — so the
  request is refused instead. Any non-zero value on that counter is an
  attempted request desync, not a tuning signal.
