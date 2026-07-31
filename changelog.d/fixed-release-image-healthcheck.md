- **`Dockerfile.release` no longer declares a `HEALTHCHECK` that no published
  image has ever had.** `HEALTHCHECK` is a Docker extension: the OCI image
  configuration reserves the `Healthcheck` key without defining it, buildkit
  exports OCI media types for every image result, and the field is dropped on
  the way out. `ghcr.io/openprx/prx-waf:v0.2.119` was built from a Dockerfile
  that declared one, and the config under its
  `application/vnd.oci.image.index.v1+json` holds no healthcheck anywhere.
  Podman is blunter about the same mechanism and prints "HEALTHCHECK is not
  supported for OCI image format and will be ignored" on every build.

  Keeping the instruction would mean exporting Docker media types, and buildkit
  refuses that for an annotated image — `cannot export annotations with
  "oci-mediatypes=false"` — so the trade is the annotated OCI index the
  release's metadata rides on against a field Kubernetes ignores in favour of
  its own probes. The instruction is gone and the reasoning is written where it
  stood.

  No deployment loses a check. `docker-compose.yml` and
  `docker-compose.firedrill.yml` each define one that curls `/health`; the
  image was rebuilt and brought up under compose to watch the container go
  `starting` → `healthy`. Bare `docker run` never had one, and the README and
  `docs/RELEASING.md` now say to pass `--health-cmd` for it.
