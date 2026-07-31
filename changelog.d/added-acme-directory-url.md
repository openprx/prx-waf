- **`[acme] directory_url` and `ca_root_pem` let issuance target a CA other
  than Let's Encrypt.** The endpoint used to be picked from a single boolean,
  which admitted exactly the production and staging directories. Operators
  running step-ca, ZeroSSL or Buypass can now name the directory, and supply
  the root the client should trust when that CA is private. Both default to
  unset, and with them unset the URL resolution is byte-identical to before.

  The same seam is what makes the certificate path testable at all: it is how
  the new end-to-end test points issuance at a Pebble container.
