- **A stored certificate now records the validity window the CA issued, not a
  guess.** The row was written with `not_before = now`, `not_after = now + 90
  days` and the literal issuer `"Let's Encrypt"` — a description of what a
  Let's Encrypt certificate typically looks like rather than of the certificate
  in hand. Renewal selection is a comparison against `not_after` and nothing
  else, so any CA issuing a shorter window put the WAF to sleep past the
  expiry: against a CA configured for 30 days, a certificate expiring on
  2026-08-30 was recorded as good until 2026-10-29, and every column still
  looked right for the sixty days it would have served something no client
  accepts.

  The leaf is now parsed with the inspection already used by the TLS listener,
  and validated on the way in, so a certificate that does not match its key
  fails the write instead of surfacing later as a listener that will not start.
