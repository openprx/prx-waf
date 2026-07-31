- **`block_page_template` can now be set on a `[[hosts]]` entry.** The renderer
  has honoured a per-host block page since block pages existed, but only for
  hosts whose `hosts` row someone had edited by hand: the admin API does not
  surface the column and `HostEntry` had no field, so a config file that
  defined one served the built-in 403 page instead. It now reaches the runtime;
  the three placeholders (`{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`) are
  substituted and HTML-escaped as before, and an entry without the key keeps
  the built-in template.

  The three other `HostConfig` fields a `[[hosts]]` block still cannot set —
  `remote_ip`, `remarks` and `exclude_url_log` — are left out on purpose and
  now say so in `configs/default.toml`. None has a reader in the request path:
  the upstream is dialled from `remote_host`/`remote_port`, `remarks` is a
  description for the admin UI's database-backed host list, and
  `exclude_url_log` is read by no code in any crate. Accepting them would
  reproduce the `start_status` failure — a key that parses and does nothing.
