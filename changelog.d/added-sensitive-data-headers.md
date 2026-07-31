- **Sensitive-data detection now reads request headers.** It scanned the path,
  the query string and the body preview and nothing else, so a private key, an
  AWS credential marker or an operator's own configured word travelling in
  `X-Api-Key`, `Authorization` or any custom header was invisible to it.

  Headers are scanned with **two pattern tiers**, because the two pattern sets
  have opposite false-positive profiles. `Authorization`, `Cookie`,
  `X-Api-Key` and the other headers whose value *is* a credential by
  construction get the built-in patterns only — seven long literals that a JWT
  or a session cookie never contains, so a PEM key pasted into `Authorization`
  is still found while a normal login flow is not flagged. Every other header
  additionally gets the host's configured word list, which is where words like
  `token` and `secret` belong and where they do not fire on every request.

  Bounded: at most 64 headers, 16 KiB per value, 64 KiB per request, values
  over the per-value cap skipped rather than truncated (the rule
  `Lane1BodyBudget` already applies to an over-budget body). Names are
  inspected in sorted order so the caps cut deterministically.
