- **The rules that decide in code are switchable.** `[content_security]
  rules_enabled` / `rules_disabled` reached 97 rule keys and refused 18 more that
  the engine emits: the five SQL-AST structures, the nine XSS DOM constructs, the
  two XSS JS token classes and the two pickle opcode grades. The inventory
  `prx-waf rules semantic` prints is now **115 keys, 81 on and 34 off**.

  The reason those keys were out of reach was that their detectors judge parsed
  structure rather than match a pattern, so there was no regex row to leave out of
  a compile step — a fact about how a rule is evaluated that had quietly become a
  fact about what an operator could configure. `docs/lane2-latent-pressure.md`
  priced that: three of the ten benign-corpus false positives come from
  `xss.script_tag` and `xss.event_handler` alone, and the only ways to silence
  either were the whole `xss` family or the whole lane.

  Switching a code-decided rule off leaves its detector running — still parsing,
  still feeding the XSS corroboration channel — and stops it naming that one
  construct, so the next-strongest enabled construct on the same input is still
  reported. `rules semantic` prints a DECIDES column (`table` / `code`, also
  `decided_by` in `--format json`) saying which kind a rule is.

  Three XSS DOM constructs that shipped default-off behind a `#[cfg(test)]`
  constructor — `xss.object_embed`, `xss.base_href`, `xss.dangling_open_tag` —
  are reachable from `rules_enabled` for the first time, so `tests/lane2/` can
  price them. `deser.py_pickle_dangerous_global`, which has never been observed
  firing, is in the inventory for the same reason.

  `ast.comment_obfusc` is deliberately **not** switchable and naming it is refused
  with that explanation: it is the label the AST detector puts on whichever
  structure it already matched when the view carried a comment marker, so it has
  no confidence of its own and disabling it has two irreconcilable readings.
  Disabling the structure reaches it.

  Default behaviour is unchanged to the byte. With both lists empty every
  detector reproduces its shipped construct set: lane 2 shadow 139/10/2, enforce
  75/2/2, `tests/ftw/` 1824/860/373.
