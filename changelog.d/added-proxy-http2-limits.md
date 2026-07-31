- **`[proxy.http2]` tunes the HTTP/2 frame-layer DoS ceilings.**
  `max_concurrent_streams`, `max_header_list_size_bytes`, and
  `max_pending_accept_reset_streams` were fixed at whatever Pingora's
  `default_h2_options` and the `h2` crate chose. The three now default to those
  same values — so leaving the table out changes nothing — but can be lowered
  to harden the listener, and setting them explicitly pins the Rapid-Reset
  (CVE-2023-44487) reset ceiling that `default_h2_options` otherwise left
  floating at whatever `h2` version is compiled in. Startup announces the
  effective limits; a wedging value (zero streams, zero resets, a sub-1-KiB
  header ceiling) is a hard startup error. The guards themselves are the `h2`
  crate's, which already answers Rapid Reset, the CONTINUATION flood
  (CVE-2024-27316), and the control-frame floods before a request reaches any
  detector — the evidence, and why no guard is duplicated here, is in
  `docs/http2-attack-surface.md`, with an end-to-end regression in
  `tests/e2e-h2-flood.sh`.
