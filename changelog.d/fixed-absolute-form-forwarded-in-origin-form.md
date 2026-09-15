- **A routed absolute-form request reaches the origin in origin-form, with a
  `Host`.** Pingora 0.9 writes the request target to an HTTP/1.1 origin exactly
  as received, so a client sending `GET http://a.example/x HTTP/1.1` had its
  path inspected as `/x` while the origin was handed the whole URL — the same
  bytes on a compliant origin, a different request on one that treats the
  target as a path. The upstream request filter now rewrites the target to its
  path and query and, when the client sent no `Host`, supplies the routed
  authority as `Host` (Pingora's own egress only does that while the target
  still carries an authority). Origin-form, asterisk-form and h2 requests are
  untouched. `tests/e2e-http3-authority.sh` asserts the origin's request line.

  Two smaller tightenings ride along. The routing verdict `request_filter`
  acts on is a pure function with a unit test per verdict, so the wiring from
  the resolver to the two refusals no longer depends on an E2E run to notice a
  change; and an absolute-form request whose `Host` is present but empty or not
  UTF-8 is refused as a contradiction rather than routed on the authority,
  matching the byte comparison Pingora makes one layer down.
