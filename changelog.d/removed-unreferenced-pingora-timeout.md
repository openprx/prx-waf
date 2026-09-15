- **The `pingora-timeout` workspace dependency is gone.** No crate in the
  workspace referenced it — the upstream timeouts go through `PeerOptions` and
  Pingora's own timers — and `cargo machete` does not audit
  `[workspace.dependencies]`, so the entry had outlived any use unnoticed.
