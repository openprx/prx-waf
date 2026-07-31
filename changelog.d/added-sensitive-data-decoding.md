- **Sensitive-data detection decodes what it scans.** It matched raw bytes only,
  so percent-encoding, an HTML character reference or a base64 wrapper was
  enough to walk a private key past it. It now scans the field as it arrived
  plus up to three decode layers below it — percent-decoding (iterated to its
  fixed point, counting as one layer), HTML entities, and base64 tokens gated on
  the decode looking like text — reusing the Lane 2 preprocessor's decoders
  rather than growing a second copy.

  A blind base64 decode is a **guess**, so its result is scanned with the
  built-in patterns only, never with the operator's word list: a short word
  matching in guessed bytes would block a request over a coincidence. This is
  the same distinction the Lane 2 preprocessor draws between
  `Provenance::BlindDecoded` and `Provenance::HtmlEntityDecoded`.

  Bounded at 3 layers, 48 decoded texts and 128 KiB of decoded bytes per
  request. All three decoders shrink their input, so depth cannot bomb; the
  branch count is what the budgets hold. A body preview over 8 KiB is scanned
  raw, exactly as before — decoding it would re-introduce the cost that tracks
  upload size. Recorded in `docs/dos-budget.md` §1.4.

  **Neither corpus baseline moved, and neither file was touched.** Both
  harnesses configure `sensitive = false` (`tests/lane2/run.sh:375`,
  `tests/ftw/run.sh:318`) so that a hit is attributable to exactly one engine,
  which makes this a structural guarantee rather than luck — but it was replayed
  rather than argued. On `56c23e1f`: Lane 2 shadow 141 detected / 10 FP / 2
  block-FP and enforce 75 / 2 / 2, with the named `fp-block` and `fp-log` rows
  unchanged; go-ftw log **and** cloud at PL1/PL2/PL4, all six cells identical to
  the committed numbers down to every bucket, `over-block` included. Writing a
  new `recorded_from` onto numbers that did not change is how that field came to
  point at the wrong tree twice, so it still names the run that produced them.
