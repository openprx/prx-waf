- **`{cat,/etc/passwd}` is now attributed to RCE.** A brace expansion on the
  command side is one word to a parser and two words to a shell, and the two
  words are the reader and the file it opens — no space appears in the request
  at all. The existing brace rule only covers the path side (`cat /etc/{passwd,
  shadow}`), so this form was logged as directory traversal. The new rule keeps
  the same bound as its sibling: a reader first, one flat closed group, the
  sensitive path within 64 bytes. Character-splitting spellings (`{c,a,t}`) are
  deliberately not covered — brace expansion yields separate words, so they run
  nothing.
