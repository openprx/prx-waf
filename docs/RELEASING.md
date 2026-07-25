# Releasing prx-waf

This is the operator runbook for cutting a prx-waf release. Everything after
`git push --tags` is automated by
[`.github/workflows/release.yml`](../.github/workflows/release.yml); everything
before it is on you.

Releases are cut from `main` only.

---

## 1. Pre-flight

Run the full self-check gauntlet on a **clean, fully committed tree** — a dirty
tree invalidates the result, because the pipeline will build the committed
state, not your working copy.

```bash
git switch main && git pull --ff-only
git status --porcelain   # must be empty

# The admin UI is embedded by rust-embed at compile time and web/admin-ui/dist/
# is gitignored, so nothing below compiles until you build the frontend once.
(cd web/admin-ui && npm ci && npm run build)

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --all-features
cargo machete
cargo audit
cargo deny check
cargo test --workspace --all-features

# DB-gated content-security parity suite (#[ignore]d, skipped by the line above).
DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
  cargo test -p waf-engine --test content_security_engine_parity -- --ignored
```

All green, or you do not tag.

---

## 2. Bump the version

The workspace uses a single inherited version. Edit **one** place:

```toml
# Cargo.toml
[workspace.package]
version = "0.2.28"   # <- here
```

Then refresh the lockfile so the workspace members' recorded versions follow:

```bash
cargo update --workspace   # or: cargo check, which rewrites Cargo.lock
git diff Cargo.lock        # expect only the prx-waf* crate versions to move
```

Versioning rules (pre-1.0, SemVer-flavoured):

| Change                                                              | Bump  |
| ------------------------------------------------------------------- | ----- |
| Bug fix, detection tuning, dependency bump                          | patch |
| New feature, new rule set, new config key with a safe default       | minor |
| Config key removed/renamed, startup now refuses a previously valid config, admin API breaking change | minor (pre-1.0) — and say so loudly in the CHANGELOG |

The release pipeline **fails the build** if the tag does not match
`[workspace.package] version`. That check exists so a published
`prx-waf-0.2.28-*.tar.gz` can never contain a binary that reports `0.2.27`.

---

## 3. Write the CHANGELOG entry

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The release job extracts the section whose heading starts with
`## [<version>]` and uses it verbatim as the release body, so the heading must
match the tag exactly.

Rename the `## [Unreleased]` heading to the release heading and open a fresh
empty `## [Unreleased]` above it:

```markdown
## [Unreleased]

## [0.2.28] — 2026-08-01

### Security

- **(H-12)** Fix … (GHSA-xxxx-xxxx-xxxx / CVE-2026-XXXXX). Reported by @handle.

### Added
### Changed
### Fixed
### Breaking Changes
```

Rules for the entry:

- `### Security` goes **first** and names the advisory or CVE ID and the
  reporter's credit. This is the section operators grep for when deciding
  whether to page someone.
- Every `### Breaking Changes` bullet must state what an operator has to *do*,
  not just what changed. "Startup now refuses X — set `y.z = true` to keep the
  old behaviour" is useful; "hardened X" is not.
- Drop empty subsections before committing.

If no matching section exists the pipeline emits a warning and falls back to
GitHub's auto-generated commit notes. That is a degraded release — fix the
CHANGELOG instead of shipping it.

Commit the bump:

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: release 0.2.28"
git push origin main
```

Wait for CI on `main` to go green before tagging.

---

## 4. Tag and push

The tag must be `v` + the exact workspace version, matching `v*.*.*`.

```bash
git tag -a v0.2.28 -m "prx-waf 0.2.28"
git push origin v0.2.28
```

A pre-release suffix (`v0.2.28-rc.1`) is detected automatically and the GitHub
Release is marked as a pre-release.

---

## 5. What the pipeline does

`.github/workflows/release.yml`, triggered by the tag push:

| Job        | What it does                                                                                                                                                       |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `frontend` | `npm ci && npm run build` in `web/admin-ui/`, uploads `dist/` as an artifact. Built **once** so every published binary embeds a byte-identical admin UI.             |
| `gate`     | Verifies tag == workspace version, then `cargo fmt --check`, `clippy` (`-D warnings`), `cargo test --workspace --all-features`. Nothing is published if this fails.  |
| `build`    | Matrix over `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`. Downloads the UI artifact, `cargo build --release --locked -p prx-waf`, strips, tars.        |
| `publish`  | SBOM, checksums, cosign signatures, SLSA provenance, GitHub Release.                                                                                                 |

Published assets, per release:

```
prx-waf-<version>-x86_64-unknown-linux-gnu.tar.gz        (+ .sig, .pem)
prx-waf-<version>-aarch64-unknown-linux-gnu.tar.gz       (+ .sig, .pem)
prx-waf-<version>-sbom.cdx.json                          (+ .sig, .pem)
SHA256SUMS                                               (+ .sig, .pem)
```

Each tarball unpacks to `prx-waf-<version>-<target>/` containing the stripped
binary plus `configs/`, `rules/`, `migrations/`, `README.md`, `CHANGELOG.md`,
`LICENSE`, `SECURITY.md`.

Signing is **cosign keyless**: the pipeline gets a short-lived certificate from
Fulcio bound to the workflow's GitHub OIDC identity and logs the signature to
the Rekor transparency log. There is no long-lived private key in the project,
nothing to rotate, and nothing to steal. Build provenance is a SLSA attestation
stored by GitHub, verifiable with `gh attestation verify`.

Typical wall-clock: 15–35 minutes, dominated by the `gate` job.

---

## 6. Verify the published release

Do this yourself before announcing, exactly as a user would. Download the
assets from the release page:

```bash
VERSION=0.2.28
TARGET=x86_64-unknown-linux-gnu
BASE="https://github.com/openprx/prx-waf/releases/download/v${VERSION}"

curl -fLO "${BASE}/prx-waf-${VERSION}-${TARGET}.tar.gz"
curl -fLO "${BASE}/prx-waf-${VERSION}-${TARGET}.tar.gz.sig"
curl -fLO "${BASE}/prx-waf-${VERSION}-${TARGET}.tar.gz.pem"
curl -fLO "${BASE}/SHA256SUMS"
curl -fLO "${BASE}/SHA256SUMS.sig"
curl -fLO "${BASE}/SHA256SUMS.pem"
```

**a. Checksums**

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

**b. Signature (cosign keyless).** The identity check is the part that matters
— a signature alone only proves *someone* signed it. Pinning
`--certificate-identity-regexp` to this repository's release workflow and
`--certificate-oidc-issuer` to GitHub's OIDC issuer is what proves *our*
pipeline produced it.

```bash
cosign verify-blob \
  --certificate "prx-waf-${VERSION}-${TARGET}.tar.gz.pem" \
  --signature   "prx-waf-${VERSION}-${TARGET}.tar.gz.sig" \
  --certificate-identity-regexp '^https://github\.com/openprx/prx-waf/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "prx-waf-${VERSION}-${TARGET}.tar.gz"
```

Expected output: `Verified OK`. Anything else — treat the artifact as
untrusted and tell us via [SECURITY.md](../SECURITY.md).

The same command works for `SHA256SUMS` and the SBOM; swap the three filenames.

**c. Build provenance (SLSA)**

```bash
gh attestation verify "prx-waf-${VERSION}-${TARGET}.tar.gz" --repo openprx/prx-waf
```

This proves which workflow, which commit, and which runner produced the file.

**d. Smoke test the binary and the embedded UI**

```bash
tar -xzf "prx-waf-${VERSION}-${TARGET}.tar.gz"
cd "prx-waf-${VERSION}-${TARGET}"
./prx-waf --version          # must print ${VERSION}
./prx-waf --config configs/default.toml run &
curl -fsS http://127.0.0.1:9527/health
curl -fsS http://127.0.0.1:9527/ui/ | head -c 200   # real UI, not a 404
kill %1
```

Step (d) is not optional. The embedded admin UI is the one thing that can be
silently empty in a release — if `frontend` produced a stale or partial `dist/`,
everything else still passes.

**e. arm64** — if you have no arm64 host, at minimum:

```bash
file prx-waf-${VERSION}-aarch64-unknown-linux-gnu/prx-waf   # ELF 64-bit ARM aarch64
```

---

## 7. When something goes wrong

**The pipeline failed before the Release was created.** Nothing was published.
Fix the problem on `main`, then delete and re-push the tag:

```bash
git tag -d v0.2.28
git push origin :refs/tags/v0.2.28
# ... fix, commit, push main ...
git tag -a v0.2.28 -m "prx-waf 0.2.28" && git push origin v0.2.28
```

Re-using a tag is only acceptable while **no release assets have been
published**. Once artifacts exist, someone may have downloaded them, and a
mutated tag makes every recorded signature and provenance statement a lie.

**A bad release is already published.** Do not delete it and do not re-use the
version. Roll forward:

1. Immediately mark the release as a pre-release, or edit the body to start
   with a bold "**DO NOT USE — see v0.2.29**" line. Leave the assets in place;
   deleting them breaks checksum verification for people who already have them
   and destroys the transparency-log trail.
2. Fix the defect on `main`, bump to the next patch version, add a CHANGELOG
   entry that names the broken version explicitly.
3. Cut the new release and verify it per section 6.
4. If the defect is a security regression, open a GitHub Security Advisory as
   well — see [SECURITY.md](../SECURITY.md).

**The Release exists but assets are missing or unsigned.** Re-running the
`publish` job alone is safe only if the `build` artifacts are still retained (7
days). Otherwise re-run the whole workflow from the tag
(`gh run rerun <run-id> --failed`). If the workflow was already re-run and the
Release now has duplicate assets, delete the *duplicates* only, never the
originals.

**Operator downgrade path.** Every release tarball is self-contained, so
rolling a deployment back is: stop the service, unpack the previous version,
restore the previous `configs/`, start. Check the previous release's
`### Breaking Changes` section first — if it introduced a database migration,
downgrading may require restoring a DB snapshot taken before the upgrade. Take
that snapshot before every upgrade.

---

## 8. Post-release

- Confirm the OpenSSF Scorecard run on `main` did not regress.
- Confirm the container images / compose files referencing a pinned version are
  updated if you ship any.
- Close the milestone and thank external reporters credited in the CHANGELOG.
