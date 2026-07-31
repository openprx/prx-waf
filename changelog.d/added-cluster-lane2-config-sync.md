- **Lane 2 semantic configuration now reaches every node in a cluster.** It
  never had a way to travel: there is no `content_security` table, no admin
  API, and the only source was each node's own TOML — so the three configs in
  `docker-compose.cluster.yml`, none of which mention `[content_security]`, all
  ran the compiled-in `enabled = false`. The gap was wider than the DB-less
  edge nodes it was filed against; no node could be configured remotely,
  database or not.

  The config now rides the rule registry — the one synced channel a worker
  actually applies — as a singleton `Rule` under `category =
  "cluster-semantic"`, the same shape `cluster-custom` already uses. Two
  properties made this safe to add to a live wire format: `SyncedKind` is never
  serialized, so a category an older peer does not know falls through its
  existing catch-all, and an absent entry decodes to "unconfigured" rather than
  "disabled", so an older Main cannot silently switch Lane 2 off across a
  cluster.
