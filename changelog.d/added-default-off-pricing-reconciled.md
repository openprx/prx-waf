- **The thirty-one default-off prices are reconciled with the post-`v0.2.188`
  baseline.** Those prices were taken before seven rules went default-on, so they
  carried a stale premise. The two baselines differ on **twelve attack rows and
  no benign row**, and the widened synthetic-view gate cannot reach further —
  only two corpus rows carry the pattern that widening added, in raw, percent-,
  base64- or hex-decoded form, and both are already among the twelve. Seven
  detector-disjoint group runs check the argument instead of trusting it: all
  thirty-one reproduce their recorded benign contact exactly, and only four touch
  any of the twelve rows, all cross-family and all far below the score the
  expected family already carries there.

  **One price moved.** `traversal.plain_dotdot` is `+1` detection for two false
  positives, not `+2`: `traversal.sensitive_abs_ops` now recovers `trav-005` in
  the baseline, so `trav-016` is the whole of what the rule buys. It is the only
  rule in the default-off set whose detections are outnumbered by its false
  positives. Nothing was switched.
