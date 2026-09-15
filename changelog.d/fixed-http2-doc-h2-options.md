- **`docs/http2-attack-surface.md` describes the h2 options this build really
  passes.** The document said the listener ran with Pingora's built-in
  `default_h2_options()` because `h2_options` was `None`; `main.rs` has always
  passed `Some(build_h2_options(..))`, which starts from those defaults and
  then applies the three `[proxy.http2]` values. The limits it lists were
  right, the reasoning was not. The `h2` line references now all point at the
  locked 0.4.19 rather than a mix of 0.4.15 and 0.4.19, each re-read against
  that source.
