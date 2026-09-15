- **The lint gate passes on Rust 1.98.** The new `manual_is_variant_and`,
  `chunks_exact_to_as_chunks`, `unused_async_trait_impl` and widened
  `missing_const_for_fn` lints flagged thirteen sites; each is rewritten in
  the idiom the lint asks for (`is_ok_and`, `as_chunks`, `std::future::ready`
  in the test mocks, `const fn`) with no behaviour change. The 8-byte lane
  scan in `contains_marker` loses its unreachable `try_from` fallback because
  `as_chunks` proves the chunk width at compile time.
