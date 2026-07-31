#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PRX-WAF End-to-End ACME issuance test
#
# Issues a real certificate, from a real ACME server, over a real HTTP-01
# challenge that our own ChallengeStore answers. `SslManager::request_certificate`
# talks to a CA from account creation onwards, so short of a CA it cannot be
# tested at all — and the `instant-acme` 0.8 upgrade rewrote every line of it.
#
# The CA is Pebble, Let's Encrypt's test server. It signs with a throwaway CA
# generated at startup, needs no public domain and no rate-limit budget, and
# misbehaves deliberately (5% of good nonces rejected, challenges reordered) so
# that a client which got the protocol subtly wrong fails here rather than in
# production.
#
# What runs (see crates/gateway/tests/acme_pebble_e2e.rs for the assertions):
#
#   1. Issuance succeeds, the certificate is signed by Pebble's CA, carries the
#      requested domain, and its public key is the public half of the private
#      key stored in the same `certificates` row.
#   2. The control: same code, same CA, an empty challenge store. The CA asks,
#      is answered 404, and issuance must fail — otherwise test 1 proves nothing
#      about the HTTP-01 round trip.
#   3. A challenge port that accepts and then says nothing, so validation never
#      concludes. Issuance must give up inside its polling deadline and record
#      the failure — the renewal task never joins these, so one that hangs is a
#      task leaked on every renewal cycle.
#
# Then, independently of the Rust assertions, this script re-derives the public
# key from the stored PEMs with openssl, so the key-match claim does not rest on
# the same library that produced the key.
#
# Prerequisites: podman (or docker), psql, openssl, cargo.
#
# Usage:
#   ./tests/e2e-acme-pebble.sh
#   KEEP=1 ./tests/e2e-acme-pebble.sh     # leave the containers running
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-acme-e2e}"
RUNTIME="${RUNTIME:-podman}"
PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-docker.io/library/postgres:16}"

# Ports. Pebble runs on the host network so that it can reach a challenge
# responder listening on 127.0.0.1, which is where the test binds it.
PG_PORT="${PG_PORT:-15942}"
ACME_PORT="${ACME_PORT:-15400}"
ACME_MGMT_PORT="${ACME_MGMT_PORT:-15401}"
HTTP01_PORT="${HTTP01_PORT:-15402}"
TLS_ALPN_PORT="${TLS_ALPN_PORT:-15403}"

# Pebble resolves the identifier itself before fetching the challenge, so the
# name has to point back at this host from inside the container.
DOMAIN="${DOMAIN:-acme-e2e.test}"

WORK="$(mktemp -d)"

cleanup() {
    if [ "${KEEP:-0}" = "1" ]; then
        echo "KEEP=1: leaving ${PREFIX}-* containers running"
    else
        $RUNTIME rm -f "${PREFIX}-pebble" "${PREFIX}-postgres" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

for tool in "$RUNTIME" psql openssl cargo; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool not found" >&2; exit 1; }
done

# ── Pebble configuration ──────────────────────────────────────────────────────
# `certificate`/`privateKey` are the paths inside the image; the rest is ours.
# validityPeriod is deliberately NOT 90 days: the code used to assume that
# figure instead of reading the certificate, and a CA that disagrees is the only
# thing that can catch such an assumption.
write_pebble_config() {
    local file="$1" listen="$2" mgmt="$3" http01="$4" tlsalpn="$5"
    cat >"$file" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:${listen}",
    "managementListenAddress": "0.0.0.0:${mgmt}",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": ${http01},
    "tlsPort": ${tlsalpn},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "retryAfter": { "authz": 3, "order": 5 },
    "keyAlgorithm": "ecdsa",
    "profiles": {
      "default": { "description": "prx-waf e2e", "validityPeriod": 2592000 }
    }
  }
}
EOF
}

write_pebble_config "$WORK/pebble.json" "$ACME_PORT" "$ACME_MGMT_PORT" "$HTTP01_PORT" "$TLS_ALPN_PORT"

# ── Containers ────────────────────────────────────────────────────────────────
echo "── starting Postgres and Pebble ──"
$RUNTIME rm -f "${PREFIX}-pebble" "${PREFIX}-postgres" >/dev/null 2>&1 || true

$RUNTIME run -d --name "${PREFIX}-postgres" \
    -e POSTGRES_USER=prx_waf -e POSTGRES_PASSWORD=prx_waf -e POSTGRES_DB=prx_waf \
    -p "${PG_PORT}:5432" "$POSTGRES_IMAGE" >/dev/null

# --add-host is what makes $DOMAIN resolve to this host inside Pebble; Pebble
# uses the system resolver unless told otherwise, and Go's resolver reads
# /etc/hosts. That avoids a third container (pebble-challtestsrv) whose only job
# would be to answer one A record.
$RUNTIME run -d --name "${PREFIX}-pebble" --network host \
    -v "$WORK/pebble.json:/pebble-config.json:ro,Z" \
    --add-host "${DOMAIN}:127.0.0.1" \
    "$PEBBLE_IMAGE" -config /pebble-config.json >/dev/null

# Pebble mints its CA at startup and serves the directory over HTTPS with a
# certificate from the fixed test root shipped in the image; that root is what
# the client has to trust to speak to it at all.
$RUNTIME cp "${PREFIX}-pebble:/test/certs/pebble.minica.pem" "$WORK/pebble.minica.pem"

echo -n "waiting for Pebble"
for _ in $(seq 1 60); do
    if curl -sk --max-time 2 "https://127.0.0.1:${ACME_PORT}/dir" >/dev/null 2>&1; then
        echo " up"; break
    fi
    echo -n "."; sleep 1
done

export DATABASE_URL="postgresql://prx_waf:prx_waf@127.0.0.1:${PG_PORT}/prx_waf"
echo -n "waiting for Postgres"
for _ in $(seq 1 60); do
    if psql "$DATABASE_URL" -c 'SELECT 1' >/dev/null 2>&1; then echo " up"; break; fi
    echo -n "."; sleep 1
done

# ── Run ───────────────────────────────────────────────────────────────────────
export PEBBLE_DIRECTORY_URL="https://127.0.0.1:${ACME_PORT}/dir"
export PEBBLE_ROOT_PEM="$WORK/pebble.minica.pem"
export PEBBLE_HTTP01_PORT="$HTTP01_PORT"
export PEBBLE_TEST_DOMAIN="$DOMAIN"

echo "── cargo test -p gateway --test acme_pebble_e2e ──"
# --test-threads=1: the tests bind the same challenge ports and share one CA.
# The status is captured rather than allowed to abort the script, so that the
# openssl cross-check below still runs and reports on whatever was issued.
RUST_STATUS=0
cargo test --manifest-path "$ROOT/Cargo.toml" -p gateway --test acme_pebble_e2e -- \
    --ignored --nocapture --test-threads=1 || RUST_STATUS=$?

# ── Independent check of the key match ────────────────────────────────────────
# The Rust assertion compares the certificate's SubjectPublicKeyInfo with one
# derived by rcgen, the same crate that generated the key. openssl deriving the
# same answer from the stored PEMs removes that crate from the argument.
echo
echo "── openssl cross-check of the stored certificate and key ──"
psql "$DATABASE_URL" -At -c \
    "SELECT cert_pem FROM certificates WHERE host_code LIKE 'acme-ok-%' AND status='active' ORDER BY created_at DESC LIMIT 1" \
    >"$WORK/cert.pem"
psql "$DATABASE_URL" -At -c \
    "SELECT key_pem FROM certificates WHERE host_code LIKE 'acme-ok-%' AND status='active' ORDER BY created_at DESC LIMIT 1" \
    >"$WORK/key.pem"

if [ -s "$WORK/cert.pem" ] && [ -s "$WORK/key.pem" ]; then
    openssl x509 -in "$WORK/cert.pem" -noout -subject -issuer -dates -ext subjectAltName
    cert_pub="$(openssl x509 -in "$WORK/cert.pem" -noout -pubkey)"
    key_pub="$(openssl pkey -in "$WORK/key.pem" -pubout)"
    if [ "$cert_pub" = "$key_pub" ]; then
        echo "  PASS: certificate public key == public key of the stored private key"
        echo "$cert_pub"
    else
        echo "  FAIL: the stored private key does not belong to the stored certificate" >&2
        RUST_STATUS=1
    fi
else
    echo "  FAIL: no active certificate row to cross-check" >&2
    RUST_STATUS=1
fi

exit $RUST_STATUS
