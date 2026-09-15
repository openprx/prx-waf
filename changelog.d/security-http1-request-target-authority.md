- **An HTTP/1.1 request target that carries an authority is routed by one
  rule set, and the forms this proxy cannot vouch for are refused.** Pingora
  0.8 failed to parse absolute-form (`GET http://a.example/x HTTP/1.1`) and
  authority-form targets, so HTTP/1.1 routing could only ever read `Host`;
  Pingora 0.9 parses them, keeps the authority out of `Uri` and writes the
  original target to the origin verbatim. The resolver now reads the raw
  target through Pingora's own classifier: `Host` alone routes; a target
  authority alone routes; a byte-unequal pair is refused with 400 exactly as
  the h2/h3 contradiction is; and a target that is neither origin-form nor
  absolute-form — authority-form outside CONNECT, an opaque `scheme:rest`, a
  non-HTTP scheme — is refused with 400, since the origin would be asked to
  interpret bytes the detectors never saw. That last refusal is counted as
  `prxwaf_budget_events_total{subsystem="request_headers",limit="unsupported_request_target"}`
  and logged with `action="block"`; a non-zero value is a probe. The unit
  tests that pin what Pingora hands the resolver were rewritten from the 0.8
  tripwire into assertions of the 0.9 boundary, so the next change there fails
  a test before it can change routing.
