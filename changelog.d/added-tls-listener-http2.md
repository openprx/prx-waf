- **The TLS listener speaks HTTP/2.** ALPN now advertises `h2` ahead of
  `http/1.1`, so a browser negotiates HTTP/2 and a client that only speaks
  HTTP/1.1 is still served. Nothing else about the endpoint changes: the same
  routing, the same detectors, the same body inspection, and the same
  certificate.

  It could not be switched on before, because routing read the `Host` header
  and Pingora's h2 server does not write one — it delivers `:authority` in the
  request URI and passes the field map through untouched, so every compliant h2
  request would have routed on the empty string and got a 404. That is the same
  defect HTTP/3 shipped with, and it now has one fix rather than three:
  `gateway::authority::route_authority` decides which site a request addressed,
  for all three protocols. HTTP/1.1 is unaffected by construction — Pingora
  refuses the two request-target forms that carry an authority, so that path
  reads the `Host` field it always read.
