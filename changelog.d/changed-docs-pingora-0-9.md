- **Every in-code and documentation reference to Pingora source now cites
  0.9.0.** The graceful-upgrade, worker-thread, drain, ALPN, h2 routing,
  upstream-timeout, TLS listener and HTTP/2 attack-surface notes pointed at
  `pingora-core-0.8.1` / `pingora-proxy-0.8.1` line numbers; each was
  re-read against 0.9.0 and re-pointed, and the HTTP/2 note gained the
  per-connection budget Pingora 0.9 applies to streams it rejects at accept.
  One statement changed in substance: the "no SNI" caveat on
  `[proxy] listen_addr_tls` no longer says Pingora's rustls backend cannot
  select a certificate per hostname — since 0.9 it can, through
  `set_cert_resolver` — but that this proxy does not yet wire that hook, so
  one certificate per TLS port remains the contract.
