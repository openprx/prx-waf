- **`[content_security.budget] max_list_items` is gone.** It never bounded
  anything: the key was parsed, validated non-zero and compiled into the
  per-request budget, and no code path read it. It is deleted rather than
  wired up, because the only limit it could plausibly have driven —
  the structured extractor's `MAX_VALUE_NODES = 256` — bounds nodes visited
  while walking a single GraphQL argument value, not list items, and adopting
  the key's 1 024 there would have quadrupled an attacker-reachable walk to make
  a name come true. A configuration file that still sets the key loads
  unchanged; the key is ignored, as it always was. Detection is unaffected —
  both the Lane 2 corpus and the go-ftw CRS baselines are unmoved.
