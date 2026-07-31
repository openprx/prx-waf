- **`start_status = false` in the configuration file now closes the site.** It
  never did. `[[hosts]]` entries are deserialized into a struct that had no
  `start_status` field, and serde drops unknown keys without a word, so the key
  parsed cleanly and the host kept its default `true`: an operator who wrote
  `start_status = false` to take a site down got a successful startup and a site
  that carried on serving. The switch worked only through the admin API or a
  direct database row. A closed host answers `503 Service Unavailable` on both
  HTTP/1.1 and HTTP/3, as it always has when the flag came from the database.
