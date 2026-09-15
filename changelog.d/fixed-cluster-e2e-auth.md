- **`tests/e2e-cluster.sh` reads the cluster's own answers again.** The script
  probed `/api/cluster/status` without a token, and that route has sat behind
  the admin API's authentication since the cluster work landed, so every role
  read came back as `unknown` and the election assertion failed regardless of
  what the cluster did. It now logs in once (`/api/auth/login`, the
  `access_token` field, `ADMIN_PASSWORD` defaulting to the compose file's
  seed) and sends the token with every status read. The rule-sync step, which
  called `/api/v1/rules` — a path the API never had — is marked as not
  exercised instead of silently skipping; rewriting it against
  `/api/custom-rules` in a way that proves propagation rather than a shared
  database is separate work.
