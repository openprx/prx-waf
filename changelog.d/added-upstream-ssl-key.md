- **`upstream_ssl` splits "the site is TLS" from "the origin is TLS".** `ssl`
  was answering both questions with one bit. It is the flag ACME issues a
  certificate against — a statement about what clients speak to the site — and
  it was also, on HTTP/1.1 and HTTP/3 alike, the switch that decided whether
  this proxy dialled the origin over TLS. Those are independent in the
  commonest reverse proxy there is: public HTTPS in front, plaintext
  `127.0.0.1:8080` behind. Writing the only thing that expresses the first
  (`ssl = true`) silently asserted the second, and every request to that host
  returned `502 Bad Gateway` with nothing in the log tying the two together.

  `upstream_ssl = false` now gives a TLS site a cleartext origin, and
  `upstream_ssl = true` gives a plaintext site an encrypted one. Both data
  paths read it through one predicate, so they cannot drift apart on the
  question again.
