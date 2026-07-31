//! End-to-end ACME issuance against a real ACME server.
//!
//! `SslManager::request_certificate` talks to a CA from account creation
//! onwards, and every previous test of this file stopped at the two things that
//! need no server: the challenge store, and a self-signed certificate. The
//! function itself — account, order, HTTP-01 round trip, CSR, finalize, download
//! and the row it writes — had never once been executed. That is a poor place
//! for a code path to be after `instant-acme` 0.8 rewrote its whole API.
//!
//! So these tests issue a certificate for real. The CA is
//! [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's own test
//! server: it implements RFC 8555, signs with a throwaway CA it generates at
//! startup, and needs neither a public domain nor a rate-limit budget. It also
//! misbehaves on purpose — by default it rejects 5% of otherwise-good nonces and
//! reorders challenges — which is the point. A client that quietly assumed
//! either would pass against a well-behaved mock and fail in production.
//!
//! The harness is `tests/e2e-acme-pebble.sh`; it starts Pebble and Postgres,
//! exports the variables below and runs this file with `--test-threads=1`
//! (the tests bind fixed ports and share one CA, so they must not overlap):
//!
//! ```bash
//! ./tests/e2e-acme-pebble.sh
//! ```
//!
//! | Variable | Meaning |
//! |---|---|
//! | `DATABASE_URL` | Postgres the certificate row is written to |
//! | `PEBBLE_DIRECTORY_URL` | ACME directory of the cooperative Pebble |
//! | `PEBBLE_ROOT_PEM` | Root that signed Pebble's *own* HTTPS certificate |
//! | `PEBBLE_HTTP01_PORT` | Port Pebble fetches HTTP-01 challenges on |
//! | `PEBBLE_TEST_DOMAIN` | Domain to issue for; must resolve to this host *inside* Pebble |

// The prints are the point under `--nocapture`: what was issued, by whom, and
// how long the client waited is evidence a reader can check, not decoration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway::{ChallengeStore, SslManager};
use rcgen::{KeyPair, PublicKeyData as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use waf_storage::{Database, models::Certificate};
use x509_parser::pem::Pem;
use x509_parser::prelude::X509Certificate;

/// The deadline `request_certificate` gives its `RetryPolicy`. Mirrored rather
/// than imported because it is a private detail of that function; if it is ever
/// raised, this constant is the reminder that the renewal task's worst case
/// moves with it.
const POLL_DEADLINE: Duration = Duration::from_mins(1);

// ── Environment ───────────────────────────────────────────────────────────────

fn required_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run these tests through tests/e2e-acme-pebble.sh, which provisions Pebble")
    })
}

fn required_port(name: &str) -> u16 {
    required_var(name).parse().expect("port must be a u16")
}

fn test_domain() -> String {
    std::env::var("PEBBLE_TEST_DOMAIN").unwrap_or_else(|_| "acme-e2e.test".to_string())
}

/// Install the process-level rustls `ring` `CryptoProvider`.
///
/// Not a test detail: `request_certificate` reaches the ACME directory over
/// HTTPS, and with no provider installed rustls panics rather than returning an
/// error. The daemon does this at `crates/prx-waf/src/main.rs:386` before
/// anything else, so production is covered; any other embedder of `SslManager`
/// has to do the same. `install_default` errors only when already installed,
/// which makes it idempotent across these tests.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn connect_db() -> Arc<Database> {
    let url = required_var("DATABASE_URL");
    let db = Database::connect(&url, 5).await.expect("connect Postgres");
    db.migrate().await.expect("migrate");
    Arc::new(db)
}

/// A per-test `host_code`. The column is `VARCHAR(32)`, and scoping every
/// lookup to a fresh value keeps repeated runs against the same database from
/// reading each other's rows.
fn unique_host_code(prefix: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}", id.get(..12).unwrap_or(id.as_str()))
}

fn manager(db: &Arc<Database>, directory_url: String) -> Arc<SslManager> {
    Arc::new(
        SslManager::new(Arc::clone(db), "acme-e2e@prx-waf.test", false).with_directory(
            Some(directory_url),
            Some(PathBuf::from(required_var("PEBBLE_ROOT_PEM"))),
        ),
    )
}

async fn certificate_row(db: &Database, host_code: &str) -> Certificate {
    let mut rows = db.list_certificates(Some(host_code)).await.expect("list certificates");
    assert_eq!(rows.len(), 1, "expected exactly one certificate row for {host_code}");
    rows.remove(0)
}

// ── HTTP-01 responder ─────────────────────────────────────────────────────────

/// Serves `/.well-known/acme-challenge/{token}` out of a `ChallengeStore`, the
/// way the Pingora proxy does.
///
/// The answer itself comes from `ChallengeStore::response_for_path`, which is
/// the production function `WafProxy::request_filter` calls — so the prefix it
/// matches and the body it returns are under test here, not re-implemented.
/// What is *not* covered is the Pingora layer around it: this listener parses
/// the request line itself rather than running a real proxy session.
struct Responder {
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

/// Bind the challenge port, waiting out a predecessor.
///
/// Pebble fetches HTTP-01 on one configured port, so every test in this file
/// answers on the same one. `--test-threads=1` keeps them from overlapping, but
/// a `JoinHandle::abort` does not release the socket synchronously, and a test
/// that panicked never got to release it at all.
async fn bind_challenge_port(port: u16) -> TcpListener {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let mut last = None;
    for _ in 0..50 {
        match TcpListener::bind(addr).await {
            Ok(listener) => return listener,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("bind HTTP-01 responder on {addr}: {last:?}")
}

impl Responder {
    async fn spawn(store: Arc<ChallengeStore>, port: u16) -> Self {
        let listener = bind_challenge_port(port).await;
        let hits = Arc::new(AtomicUsize::new(0));

        let served = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let store = Arc::clone(&store);
                let served = Arc::clone(&served);
                tokio::spawn(async move {
                    let mut buf = Vec::with_capacity(1024);
                    let mut chunk = [0_u8; 512];
                    // Read the request head. HTTP-01 is a bodyless GET, so the
                    // blank line that ends the head ends the request.
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                        }
                    }
                    served.fetch_add(1, Ordering::SeqCst);

                    let head = String::from_utf8_lossy(&buf);
                    let path = head
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();

                    let response = store.response_for_path(&path).map_or_else(
                        || "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                        |key_auth| {
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: \
                                 close\r\n\r\n{key_auth}",
                                key_auth.len()
                            )
                        },
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });

        Self { hits, task }
    }

    /// Accept connections and then say nothing at all, holding the CA's
    /// validation open. Used to keep an order `pending` for as long as the test
    /// needs to observe how the client waits.
    async fn spawn_silent(port: u16) -> Self {
        let listener = bind_challenge_port(port).await;
        let hits = Arc::new(AtomicUsize::new(0));

        let served = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                served.fetch_add(1, Ordering::SeqCst);
                // Hold the socket open. Closing it would answer the CA with a
                // reset, which it treats as a failed validation — the opposite
                // of the stall this responder exists to produce. Bounded so a
                // long run cannot exhaust file descriptors.
                held.push(stream);
                if held.len() > 64 {
                    held.remove(0);
                }
            }
        });

        Self { hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Stop listening and wait until the socket is actually gone, so the next
    /// test can take the port. `Drop` alone only fires the abort.
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

// ── Certificate helpers ───────────────────────────────────────────────────────

/// Every PEM block in `pem`, kept alive so the parsed certificates can borrow.
fn pem_blocks(pem: &str) -> Vec<Pem> {
    Pem::iter_from_buffer(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM must parse")
}

fn parse_leaf(blocks: &[Pem]) -> X509Certificate<'_> {
    blocks
        .first()
        .expect("at least one PEM block")
        .parse_x509()
        .expect("leaf must be a valid X.509 certificate")
}

fn subject_alt_names(cert: &X509Certificate<'_>) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some((*dns).to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// The whole issuance path, end to end, against a real CA.
///
/// Asserts, in order of what would break silently:
///
///   1. Pebble asked us for the challenge and our `ChallengeStore` answered.
///   2. A certificate came back, signed by Pebble's CA — not self-signed, not
///      anything this process could have produced alone.
///   3. **The certificate carries the public key of the private key we stored.**
///      This is the one that motivated the test. `instant-acme` 0.8 offers
///      `Order::finalize()`, which generates a key pair internally and returns
///      it; we deliberately call `finalize_csr()` with a CSR over our own rcgen
///      key instead, because the private key has to be the one that ends up in
///      the database next to the certificate. If those two ever drifted apart
///      the TLS listener would load a certificate and a key that do not match,
///      and nothing before this test would have noticed.
///   4. The row is `active` with both PEMs, which is what the listener reads.
///   5. The challenge token is gone from the store afterwards.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live Postgres + a Pebble ACME server; run tests/e2e-acme-pebble.sh"]
async fn acme_http01_issues_a_certificate_for_the_key_we_stored() {
    install_crypto_provider();
    let db = connect_db().await;
    let domain = test_domain();
    let host_code = unique_host_code("acme-ok");

    let ssl = manager(&db, required_var("PEBBLE_DIRECTORY_URL"));
    let responder = Responder::spawn(Arc::clone(&ssl.challenges), required_port("PEBBLE_HTTP01_PORT")).await;

    let cert_id = Arc::clone(&ssl)
        .request_certificate(&host_code, &domain)
        .await
        .expect("ACME issuance must succeed against Pebble");

    // 1. The CA really came to us for the answer.
    assert!(
        responder.hits() > 0,
        "Pebble never fetched the HTTP-01 challenge; the order cannot have been validated by us"
    );

    let row = certificate_row(&db, &host_code).await;
    assert_eq!(row.id, cert_id);
    assert_eq!(row.domain, domain);

    // 4. Stored in the shape the TLS listener expects.
    assert_eq!(row.status, "active", "error_msg: {:?}", row.error_msg);
    let cert_pem = row.cert_pem.as_deref().expect("cert_pem stored");
    let key_pem = row.key_pem.as_deref().expect("key_pem stored");

    let blocks = pem_blocks(cert_pem);
    assert!(
        blocks.len() >= 2,
        "expected leaf + issuer chain from the CA, got {} PEM block(s)",
        blocks.len()
    );
    let leaf = parse_leaf(&blocks);

    // 2. Issued by the CA, for the domain we asked for.
    let issuer = leaf.issuer().to_string();
    assert!(
        issuer.contains("Pebble"),
        "certificate was not issued by the Pebble CA; issuer = {issuer}"
    );
    assert!(
        subject_alt_names(&leaf).contains(&domain),
        "domain {domain} missing from SANs {:?}",
        subject_alt_names(&leaf)
    );

    // 3. The public key in the certificate is the public half of the private
    //    key sitting in the same row. Compared twice: the whole
    //    SubjectPublicKeyInfo, and the bare key bits inside it, so a difference
    //    in DER framing cannot be mistaken for a matching key or the reverse.
    let stored_key = KeyPair::from_pem(key_pem).expect("stored key_pem must parse as a key pair");
    assert_eq!(
        stored_key.subject_public_key_info(),
        leaf.tbs_certificate.subject_pki.raw,
        "certificate SubjectPublicKeyInfo does not match the stored private key — the CSR was signed for a key we \
         did not keep"
    );
    assert_eq!(
        stored_key.public_key_raw(),
        leaf.tbs_certificate.subject_pki.subject_public_key.data.as_ref(),
        "certificate public key bits do not match the stored private key"
    );

    // 5. Nothing left behind to serve.
    assert!(
        ssl.challenges
            .response_for_path("/.well-known/acme-challenge/anything")
            .is_none(),
        "challenge store still holds a token after issuance"
    );

    println!("issued for {domain}: issuer={issuer} subject={}", leaf.subject());
    println!(
        "  validity: {} .. {}",
        leaf.validity().not_before,
        leaf.validity().not_after
    );
    println!("  chain blocks: {}", blocks.len());
    println!(
        "  stored row: id={} status={} not_after={:?}",
        row.id, row.status, row.not_after
    );
    responder.shutdown().await;
}

/// The control: the same code, the same CA, the same domain — with the one
/// element under test removed.
///
/// The HTTP-01 responder here is wired to an *empty* `ChallengeStore` instead of
/// the manager's, which is exactly the effect of never recording the token. The
/// request still arrives, and is answered 404. Issuance must fail, and the row
/// must say so.
///
/// Without this, a passing issuance test proves much less than it looks like it
/// does: an ACME client that skipped the challenge entirely would still be green
/// if the CA happened to authorize the identifier for another reason.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live Postgres + a Pebble ACME server; run tests/e2e-acme-pebble.sh"]
async fn acme_issuance_fails_when_the_challenge_store_cannot_answer() {
    install_crypto_provider();
    let db = connect_db().await;
    let domain = test_domain();
    let host_code = unique_host_code("acme-404");

    let ssl = manager(&db, required_var("PEBBLE_DIRECTORY_URL"));
    let empty = Arc::new(ChallengeStore::new());
    let responder = Responder::spawn(empty, required_port("PEBBLE_HTTP01_PORT")).await;

    let result = Arc::clone(&ssl).request_certificate(&host_code, &domain).await;

    assert!(
        result.is_err(),
        "issuance succeeded without a served challenge — the HTTP-01 round trip is not what makes the other test pass"
    );
    assert!(
        responder.hits() > 0,
        "Pebble never asked for the challenge, so this run proves nothing about the store"
    );

    let row = certificate_row(&db, &host_code).await;
    assert_eq!(
        row.status, "error",
        "failed issuance must not leave a usable-looking row"
    );
    assert!(row.cert_pem.is_none(), "no certificate should have been stored");

    println!("control run failed as required: {}", result.unwrap_err());
    responder.shutdown().await;
}

/// A CA that never answers cannot hang the renewal task.
///
/// `renew_due_certificates` spawns one of these per due certificate and never
/// joins them, so an issuance that blocks forever is a task that accumulates
/// silently every renewal cycle. Before the 0.8 upgrade the wait was two
/// hand-written loops with fixed sleeps and a bounded iteration count; it is now
/// `poll_ready` under a `RetryPolicy` with an explicit one-minute deadline, and
/// this is the test that the deadline is real.
///
/// The challenge port is answered by a socket that accepts and then says
/// nothing, so the CA's validation hangs and the order stays `pending` for as
/// long as anyone cares to wait. The call must come back anyway — bounded by the
/// policy, with the failure recorded on the row rather than left in memory.
///
/// The lower bound matters as much as the upper one: an immediate error would
/// also satisfy "did not hang", and would mean the polling loop was never
/// exercised.
///
/// What this test does *not* show is the `Retry-After` handling that replaced
/// the old fixed sleeps. `RetryState::wait` does prefer the CA's own figure over
/// its backoff — but Pebble only sends the header on an order while the order is
/// `processing` (`wfe.go`), and `ca.CompleteOrder` has no delay in it, so that
/// window shuts before the first poll. Its other `Retry-After` goes on the
/// *authorization*, which `poll_ready` never fetches: it polls the order URL.
/// Neither is reachable from here, so the claim rests on reading
/// `instant-acme`'s source, not on this harness.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires live Postgres + a Pebble ACME server; run tests/e2e-acme-pebble.sh"]
async fn acme_issuance_gives_up_within_the_polling_deadline() {
    install_crypto_provider();
    let db = connect_db().await;
    let domain = test_domain();
    let host_code = unique_host_code("acme-stall");

    let ssl = manager(&db, required_var("PEBBLE_DIRECTORY_URL"));
    let responder = Responder::spawn_silent(required_port("PEBBLE_HTTP01_PORT")).await;

    let started = Instant::now();
    let result = Arc::clone(&ssl).request_certificate(&host_code, &domain).await;
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "the order can never become ready: nothing answers the challenge"
    );
    assert!(
        elapsed < POLL_DEADLINE,
        "polling ran {elapsed:?}, past the {POLL_DEADLINE:?} deadline the RetryPolicy is supposed to enforce"
    );
    assert!(
        elapsed > Duration::from_secs(5),
        "gave up after only {elapsed:?}; that is too fast to have polled, so the failure is not the timeout under test"
    );
    assert!(
        responder.hits() > 0,
        "the CA never attempted validation, so the order may have failed for an unrelated reason"
    );

    let row = certificate_row(&db, &host_code).await;
    assert_eq!(
        row.status, "error",
        "a timed-out order must be recorded, not just dropped"
    );
    assert!(row.cert_pem.is_none());

    println!("gave up after {elapsed:?}: {}", result.unwrap_err());
    responder.shutdown().await;
}
