- **A per-host sensitive pattern no longer appears in the detection detail.**
  The detail read `Sensitive pattern '<the operator's pattern>' found in …`,
  and it is persisted to `security_events`, shown in the admin UI and pushed
  off the box by the community reporter. For this feature the needle routinely
  *is* the secret — an operator blocking a leaked API key pastes the key in as
  the pattern — so the check re-leaked exactly what it exists to stop. Custom
  hits now report `custom #<n>`, the pattern's 1-based position in the list
  `GET /api/sensitive-patterns` returns in the same order. Built-in hits still
  name the literal; those are compile-time constants in the source.
