- **`cat${IFS}/etc/passwd` now reads as a command execution rather than a path
  disclosure.** The semantic preprocessor's shell de-obfuscation always claimed
  to collapse `${IFS}` to a space, and its replacement step always did — but the
  fast-path guard in front of it tested for the substring `$IFS`, which `${IFS}`
  does not contain, so the braced spelling was declined at the door and no
  normalised view was ever produced. The braced form is the one attackers
  actually send (it needs no separator behind it), and it was reaching the
  detectors as an unadorned `/etc/passwd`: logged, but attributed to directory
  traversal instead of RCE, and invisible entirely when the target was
  `/proc/self/environ`, which no default-on traversal rule covers.
