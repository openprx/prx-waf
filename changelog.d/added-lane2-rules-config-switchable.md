- **Lane 2 rules can be switched on and off from config.** `[content_security]`
  takes `rules_enabled` and `rules_disabled`, two lists of rule keys that amend
  the state each detector rule ships in. Both are empty by default and the
  shipped detector sets are unchanged.

  Every Lane 2 rule carried a `default_on` flag that was a `bool` literal in a
  Rust table, read at construction, with the "compile everything" path reachable
  only from `#[cfg(test)]`. So a rule that shipped off could not be turned on
  without editing the engine and cutting a release — which meant
  `docs/lane2-blind-spots.md` could attribute fifteen of the forty blind corpus
  rows to rules that already exist and already clear their thresholds, and could
  not verify a single one of them. That number was arithmetic. The rules are
  default-off because nobody has priced their false positives, `tests/lane2/` is
  the instrument that would price them, and until now the experiment could not
  be set up.

  This ships the capability and none of the decisions: no rule changes state.

  A key that names no rule **stops startup**, quoting the key back and
  suggesting the near miss when there is exactly one. It is not warned about and
  not ignored, because a rule switch that silently does nothing is
  indistinguishable from one that works — the defect this repository already
  shipped as `start_status`, `max_list_items` and `listen_addr_tls`. The same
  key in both lists is refused too; there is no precedence rule because there is
  no obvious reading of that config.

  The switch is two-directional. Disabling a rule is a detection this WAF stops
  performing, so every disabled key is named in a startup `WARN` — but the
  alternative for an operator with one misfiring rule is turning off its family
  or the whole lane, which costs more detection than the rule was producing.
  `prx-waf rules disable` has offered the same thing for CRS rules for far
  longer.
