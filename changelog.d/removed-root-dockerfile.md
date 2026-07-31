- **The root `Dockerfile` is gone.** It compiled the workspace inside a
  `rust:1.86-slim-bookworm` builder, and nothing in the repository built it —
  no compose file, no workflow, no documented command. Left alone since the
  Phase 5 commit that introduced it, it had stopped working: the dependency
  graph now floors at rustc 1.94 (wasmtime 47, cranelift 0.134, sqlx 0.9), and
  a real `podman build` of it dies with `error: rustc 1.86.0 is not supported by
  the following packages`. Bumping the pin would not have been enough — the
  builder installs no cmake, which `aws-lc-sys` needs, and no Node, so
  `rust-embed` would compile an empty `web/admin-ui/dist` into the binary and
  the admin UI would 404 out of a container reporting itself healthy.

  Building an image from a source checkout is still possible and still
  documented: `cargo build --release` followed by
  `docker compose -f docker-compose.yml -f docker-compose.build.yml up -d
  --build`, which is the path `Dockerfile.prebuilt` serves and which three
  compose files exercise. Released images come from `Dockerfile.release`.
