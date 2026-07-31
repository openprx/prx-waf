- **The `rsa` crate is out of the dependency graph, and its advisory exemption
  with it.** RUSTSEC-2023-0071 (Marvin timing sidechannel, no fixed release)
  was the longest-argued entry in `deny.toml`: `rsa` arrived through
  jsonwebtoken's `rust_crypto` feature, which bundles it with the HMAC code
  this WAF actually uses and offers no way to take one without the other. The
  admin API now signs and verifies its JWTs through jsonwebtoken's `aws_lc_rs`
  backend instead, which drops `rsa` and twenty-one of its transitive
  dependencies. Nothing new is linked in for it: aws-lc-rs has been in the tree
  since the Pingora TLS backend was wired up.

  Tokens issued by an older build stay valid across the upgrade, and tokens
  issued by this build are accepted by an older one — both backends compute the
  same RFC 7515 HMAC-SHA256, and both directions were tested against a real
  process before the exemption was deleted. Operators need do nothing; no
  re-login, no secret rotation.
