- **`prx-waf rules semantic`** prints the Lane 2 rule inventory — key, family,
  detector, confidence, the state it ships in, and the state the loaded config
  gives it — with `--family`, `--state on|off|overridden` and `--format json`.
  It is the only way to read the vocabulary `rules_enabled` / `rules_disabled`
  accept, and it resolves the switches leniently so it still runs against the
  config whose typo just refused to start. (When this shipped it also stated what
  it did not cover — the AST SQLi detector and both XSS detectors decided in code
  and exposed no switchable rule. That gap is closed above; the command now prints
  a DECIDES column instead.)
