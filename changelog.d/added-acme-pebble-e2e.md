- **Certificate issuance is exercised against a real ACME server on every CI
  run.** The path had no coverage at all: two unit tests around the challenge
  store and the self-signed fallback, and nothing that spoke ACME. The
  `instant-acme` 0.8 upgrade rewrote `request_certificate` end to end — account
  construction, a borrowing authorization stream, challenge handles,
  `finalize_csr`, the polling loop — with the compiler as the only witness.

  A Pebble container now issues a genuine certificate through our own
  `ChallengeStore`, and the test asserts what the compiler cannot: that the
  certificate's `SubjectPublicKeyInfo` equals the public key of the private key
  we stored. 0.8's `finalize()` generates a key of its own, and swapping it in
  keeps issuance green — the key check is what catches it. Two more cases cover
  a challenge the CA cannot fetch and a CA that accepts a connection and never
  answers, so the deadline is observed rather than assumed. Pebble's injected
  chaos is left on.
