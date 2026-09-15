- **Two advisory exemptions are gone with the Pingora 0.9 upgrade.**
  RUSTSEC-2024-0437 (`protobuf` v2, reached only through `pingora-core` ->
  `prometheus` 0.13) and RUSTSEC-2025-0069 (`daemonize`, unmaintained, reached
  only through `pingora-core`) are deleted from `deny.toml` and
  `.cargo/audit.toml`: Pingora 0.9.0 moved its Prometheus integration into a
  separate optional crate this workspace does not take and replaced
  `daemonize` with `daemonix`, and `cargo tree -i` no longer matches either
  crate. The two entries the same crate family still needs — `derivative`
  (RUSTSEC-2024-0388, `pingora-core` 0.9.0) and `rustls-pemfile`
  (RUSTSEC-2025-0134, `pingora-rustls` 0.9.0, directly and through
  `rustls-native-certs` 0.7.3) — were re-verified against the new tree, the
  evidence written into the entries, and their review dates moved to
  2026-12-01. The exemption table is down to three entries.
