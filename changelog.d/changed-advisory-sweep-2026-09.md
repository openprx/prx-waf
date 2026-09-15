- **The dependency tree is clear of the advisories that accumulated while the
  project was idle.** A semver-compatible `cargo update` moves h2 to 0.4.19
  (RUSTSEC-2026-0258), rustls to 0.23.45 (RUSTSEC-2026-0285), wasmtime to
  47.0.4 (RUSTSEC-2026-0222/0223/0268/0269) and replaces the yanked
  chacha20 0.10.1, which is also what the open Dependabot lockfile group would
  have done. The one advisory no upgrade can reach, smartstring
  (RUSTSEC-2026-0249, an unmaintained notice reached only through rhai, the
  custom-rule script engine), is exempted in `deny.toml` with the evaluated and
  rejected removal paths written down, a review date, and the upstream issue
  that retires the entry.
