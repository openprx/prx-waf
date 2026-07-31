- **A host relying on `ssl` to imply its upstream scheme is named at startup.**
  Leaving `upstream_ssl` unset still falls back to `ssl`, so no existing
  deployment changes behaviour — defaulting to plaintext instead would have
  silently downgraded an origin connection that really was encrypted, and a
  proxy that quietly stops encrypting is worse than a loud 502. The
  compatibility path is now a `WARN` per affected host instead, naming the host
  and the upstream it is about to dial over TLS. Setting `upstream_ssl` either
  way silences it.
