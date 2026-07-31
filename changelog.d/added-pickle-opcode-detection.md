- **The deserialization detector reads pickle opcodes.** The shipped
  `deser.py_pickle_global_exec` rule matches the *text* `GLOBAL` opcode,
  `c<module>\n<callable>`. `save_global` stops emitting that at protocol 4, and
  protocol 4 has been `pickle.DEFAULT_PROTOCOL` since Python 3.8: from there the
  module and the callable are two length-prefixed strings joined by a one-byte
  `STACK_GLOBAL`, with non-UTF-8 framing around them that reaches any text view
  as `U+FFFD`. So the rule caught an attacker who asked for an obsolete protocol
  and missed everything a bare `pickle.dumps()` has produced for seven years.
  That is not a tuning gap and no further regex closes it — the two names are
  never adjacent tokens in a text view.

  `deser.py_pickle_reduce_exec` (92) and `deser.py_pickle_dangerous_global` (85)
  come from an opcode walker instead. It reads the byte stream and nothing else:
  it constructs no object, imports no module, instantiates no class, and does
  not recurse — a pickle stream is flat, and a pickle nested inside another's
  `BINBYTES` payload is skipped as opaque bytes rather than re-entered. A
  module/callable pair is compared byte-wise against a closed table of execution
  primitives, and a hit reports the *table's* strings, so the detector cannot be
  made to echo the payload. Protocols 0 through 5 are covered and measured
  against byte-for-byte CPython output, including the `_compat_pickle` rewrite
  that turns `subprocess` into `commands` below protocol 3.

  Every argument length is validated against the remaining buffer before the
  read, input is capped at 4 KiB, and the simulated stack bound is set *equal* to
  that input bound so it cannot be reached — a smaller stack would have been a
  free evasion (pad with `NONE` until the walker gives up, then reduce). The
  parse is metered on `budget.max_ast_input_bytes_total`, so exhaustion marks
  `degraded` like any other parse. Base64 and hex wrappers are decoded by the
  walker itself: the preprocessor's blind gate requires the decoded bytes to be
  ≥ 85 % printable ASCII, which a binary pickle is not, and `lower_trunc`
  destroys the case a base64 token depends on.

  Measured on `tests/lane2/`: shadow detection **127 → 128** of 170
  (`deser-009`, a protocol-4 pickle base64-wrapped in a JSON field, goes from
  `blind` to detected), enforce blocking **74 → 75**, and the benign half is
  unchanged — the same **10** false positives and the same **2** blocking false
  positives, by name.
