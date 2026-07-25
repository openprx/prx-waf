//! Composition test for the response-phase plumbing.
//!
//! The unit tests in `gateway::response` cover the buffering state machine in
//! isolation. This file exercises the pieces the way the gateway wires them —
//! gate → inspector → [`ResponseCheckSet`] → [`ResponseCtx`] — with a real
//! [`ResponseCheck`] implementation standing in for the CRS `RESPONSE-95x`
//! family that the next round will attach.
//!
//! That implementation is the point: shipping a trait with no implementors
//! anywhere would mean shipping an interface nobody has ever called. These tests
//! call it, on the real types, through the real gate.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use gateway::response::{
    ResponseGate, ResponseInspectMode, ResponseInspectionPolicy, ResponseInspector, ResponseStep, gate,
};
use waf_common::{DetectionResult, HostConfig, Phase, RequestCtx, ResponseCtx};
use waf_engine::checks::{ResponseCheck, ResponseCheckSet};

/// Stand-in for CRS 951xxx (`RESPONSE-951-DATA-LEAKAGES-SQL`): an Oracle error
/// message that has escaped the origin into the response body.
struct OracleErrorLeak {
    /// How many windows this detector was shown, so a test can prove that
    /// inspection stopped where it was supposed to.
    windows_seen: Arc<AtomicUsize>,
}

impl OracleErrorLeak {
    fn new() -> Self {
        Self {
            windows_seen: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A detector plus an external handle on its window counter.
    fn counted() -> (Self, Arc<AtomicUsize>) {
        let me = Self::new();
        let counter = Arc::clone(&me.windows_seen);
        (me, counter)
    }
}

impl ResponseCheck for OracleErrorLeak {
    fn check(&self, ctx: &ResponseCtx) -> Option<DetectionResult> {
        self.windows_seen.fetch_add(1, Ordering::Relaxed);
        let body = String::from_utf8_lossy(&ctx.body_preview);
        body.contains("ORA-00933").then(|| DetectionResult {
            rule_id: Some("951230".to_string()),
            rule_name: "Oracle SQL Information Leakage".to_string(),
            phase: Phase::ResponseBody,
            detail: format!("Oracle error in response body (status {})", ctx.status),
        })
    }
}

/// Stand-in for CRS 950100: a `5xx` status is itself the leak, so this one reads
/// only the status and never the body.
struct ServerErrorLeak;

impl ResponseCheck for ServerErrorLeak {
    fn check(&self, ctx: &ResponseCtx) -> Option<DetectionResult> {
        (500..600).contains(&ctx.status).then(|| DetectionResult {
            rule_id: Some("950100".to_string()),
            rule_name: "Application Error Disclosure".to_string(),
            phase: Phase::ResponseHeaders,
            detail: format!("status {}", ctx.status),
        })
    }
}

fn request_ctx() -> RequestCtx {
    RequestCtx {
        req_id: "resp-phase-test".to_string(),
        // Built rather than parsed: a module-level helper in an integration test
        // is not inside a `#[test]` fn, so `allow-expect-in-tests` does not
        // reach it and `.expect()` here would trip the workspace lint.
        client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        client_port: 51_234,
        method: "GET".to_string(),
        host: "shop.example".to_string(),
        port: 80,
        path: "/orders".to_string(),
        query: "id=1".to_string(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
    }
}

fn html_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html; charset=utf-8".to_string());
    headers
}

fn enforce_policy(window: usize, cap: usize) -> ResponseInspectionPolicy {
    ResponseInspectionPolicy {
        mode: ResponseInspectMode::Enforce,
        window_bytes: window,
        overlap_bytes: 64.min(window.saturating_sub(1)),
        max_total_bytes: cap,
        flush_after: Duration::from_hours(1),
    }
}

/// Drive a whole response through an inspector + check set, recording every byte
/// that was actually cleared for the client and the first finding.
struct Run {
    forwarded: Vec<u8>,
    finding: Option<DetectionResult>,
    steps: Vec<ResponseStep>,
}

fn drive(inspector: &mut ResponseInspector, checks: &ResponseCheckSet, request: &RequestCtx, chunks: &[&[u8]]) -> Run {
    let mut run = Run {
        forwarded: Vec::new(),
        finding: None,
        steps: Vec::new(),
    };

    for (i, chunk) in chunks.iter().enumerate() {
        let end_of_stream = i + 1 == chunks.len();
        let mut body = Some(Bytes::copy_from_slice(chunk));
        let mut step = inspector.push(&mut body, end_of_stream);

        if let Some(window) = step.inspect.take() {
            let ctx = inspector.context(request, window, step.truncated);
            if run.finding.is_none() {
                run.finding = checks.evaluate(&ctx);
            }
        }

        // The gateway forwards whatever survives in `body` — and on a finding it
        // abandons the response instead, so nothing more is forwarded.
        if run.finding.is_some() {
            run.steps.push(step);
            break;
        }
        if let Some(out) = body {
            run.forwarded.extend_from_slice(&out);
        }
        run.steps.push(step);
    }

    run
}

// ── The shipped state: an empty set inspects nothing ─────────────────────────

#[test]
fn an_empty_check_set_is_the_gate_that_closes_first() {
    let checks = ResponseCheckSet::new();
    assert!(checks.is_empty());
    assert_eq!(checks.len(), 0);

    // This is what `WafProxy` evaluates. Everything else about the response is
    // irrelevant while it is false.
    assert_eq!(
        gate(!checks.is_empty(), true, 500, Some("text/html"), None),
        ResponseGate::NoDetectors,
    );

    // And an empty set finds nothing even if it is somehow reached.
    let ctx = ResponseCtx {
        request: request_ctx(),
        status: 500,
        headers: html_headers(),
        body_preview: Bytes::from_static(b"ORA-00933: SQL command not properly ended"),
        body_truncated: false,
    };
    assert!(checks.evaluate(&ctx).is_none());
}

// ── A registered detector actually fires ─────────────────────────────────────

#[test]
fn a_leak_split_across_chunks_is_found_and_never_forwarded() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    let mut inspector = ResponseInspector::new(enforce_policy(256, 0), 200, html_headers());
    let request = request_ctx();

    // The signature straddles a chunk boundary, which is what the window overlap
    // exists for.
    let run = drive(
        &mut inspector,
        &checks,
        &request,
        &[
            b"<html><body>query failed: ORA-",
            b"00933: SQL command not properly ended</body>",
        ],
    );

    let finding = run.finding.expect("the planted Oracle error was not detected");
    assert_eq!(finding.rule_id.as_deref(), Some("951230"));
    assert_eq!(finding.phase, Phase::ResponseBody);

    // Containment: not one byte of the leaking response reached the client.
    assert!(
        run.forwarded.is_empty(),
        "leaking bytes were released before the detector ran: {:?}",
        String::from_utf8_lossy(&run.forwarded),
    );
}

#[test]
fn a_clean_response_is_delivered_whole() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    let mut inspector = ResponseInspector::new(enforce_policy(256, 0), 200, html_headers());
    let request = request_ctx();

    let page: &[u8] = b"<html><body>Order #1 shipped</body></html>";
    let run = drive(&mut inspector, &checks, &request, &[page]);

    assert!(run.finding.is_none());
    assert_eq!(run.forwarded, page, "a clean response must arrive byte-identical");
}

#[test]
fn a_status_only_detector_never_needs_the_body() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(ServerErrorLeak)]);

    let ctx = ResponseCtx {
        request: request_ctx(),
        status: 500,
        headers: html_headers(),
        body_preview: Bytes::new(),
        body_truncated: false,
    };
    assert_eq!(checks.evaluate(&ctx).and_then(|r| r.rule_id).as_deref(), Some("950100"));

    let ctx = ResponseCtx { status: 200, ..ctx };
    assert!(checks.evaluate(&ctx).is_none());
}

// ── The streaming escape hatches, at the composition level ───────────────────

#[test]
fn an_sse_response_never_reaches_a_detector() {
    // The gate — not the inspector — is what keeps SSE out. With detectors
    // registered and a host under guard, `text/event-stream` still closes it, so
    // no inspector is ever built and the stream is untouched.
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    assert_eq!(
        gate(!checks.is_empty(), true, 200, Some("text/event-stream"), None),
        ResponseGate::MediaType,
    );
}

#[test]
fn a_compressed_html_response_never_reaches_a_detector() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    for coding in ["gzip", "br", "zstd", "deflate", "compress"] {
        assert_eq!(
            gate(!checks.is_empty(), true, 200, Some("text/html"), Some(coding)),
            ResponseGate::ContentEncoding,
            "{coding} was not treated as opaque",
        );
    }
}

#[test]
fn a_download_past_the_ceiling_is_delivered_whole_and_stops_being_scanned() {
    let (detector, windows_seen) = OracleErrorLeak::counted();
    let checks = ResponseCheckSet::from_checks(vec![Box::new(detector)]);

    let cap = 4 * 1024;
    let mut inspector = ResponseInspector::new(enforce_policy(1024, cap), 200, html_headers());
    let request = request_ctx();

    let chunk = vec![b'A'; 1024];
    let chunks: Vec<&[u8]> = std::iter::repeat_n(chunk.as_slice(), 16).collect();
    let run = drive(&mut inspector, &checks, &request, &chunks);

    assert!(run.finding.is_none());
    assert_eq!(
        run.forwarded.len(),
        16 * 1024,
        "a response past the inspection ceiling must still be delivered in full",
    );
    assert_eq!(
        run.steps.iter().filter(|s| s.over_cap).count(),
        1,
        "the ceiling crossing must be reported exactly once",
    );
    assert_eq!(
        inspector.total(),
        cap + 1024,
        "byte accounting stops once the ceiling engages",
    );
    // Four windows fill the 4 KiB ceiling and the fifth crosses it; from there
    // the detector is never called again, however much more the origin sends.
    assert_eq!(
        windows_seen.load(Ordering::Relaxed),
        5,
        "the detector kept being called after the inspection ceiling",
    );
}

/// The honest half of `ProcessPartial`: a leak that only appears **after** the
/// inspection ceiling is not caught. That is `ModSecurity`'s documented
/// behaviour too, and the reason [`ResponseCtx::body_truncated`] exists — a rule
/// must be able to tell "clean" from "clean so far".
#[test]
fn a_leak_beyond_the_ceiling_is_missed_and_the_context_says_so() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    let cap = 2048;
    let mut inspector = ResponseInspector::new(enforce_policy(1024, cap), 200, html_headers());
    let request = request_ctx();

    // Chunks 1 and 2 fill the ceiling; chunk 3 crosses it and is still scanned
    // (`ProcessPartial` scans what it has buffered before giving up); only from
    // chunk 4 on is the inspector in passthrough, which is where the leak sits.
    let filler = vec![b'A'; 1024];
    let mut tail = vec![b'B'; 1024];
    tail.extend_from_slice(b"ORA-00933: SQL command not properly ended");

    let run = drive(
        &mut inspector,
        &checks,
        &request,
        &[filler.as_slice(), filler.as_slice(), filler.as_slice(), tail.as_slice()],
    );

    assert!(
        run.finding.is_none(),
        "the test is meaningless if the post-ceiling leak was caught",
    );
    assert!(
        run.steps.iter().any(|s| s.truncated),
        "the detectors were never told they only saw a prefix",
    );
    // The response is still delivered in full — a truncated *inspection* must
    // never become a truncated *response*.
    assert_eq!(run.forwarded.len(), 3 * 1024 + tail.len());
}

// ── Observe mode: detection without interference ─────────────────────────────

#[test]
fn observe_mode_detects_the_same_leak_but_delivers_it_anyway() {
    let checks = ResponseCheckSet::from_checks(vec![Box::new(OracleErrorLeak::new())]);
    let policy = ResponseInspectionPolicy {
        mode: ResponseInspectMode::Observe,
        ..enforce_policy(256, 0)
    };
    let mut inspector = ResponseInspector::new(policy, 200, html_headers());
    let request = request_ctx();

    let page: &[u8] = b"ORA-00933: SQL command not properly ended";
    let mut body = Some(Bytes::copy_from_slice(page));
    let step = inspector.push(&mut body, true);

    // Forwarded untouched, in the same turn, before any verdict exists.
    assert_eq!(body.as_deref(), Some(page));

    let window = step.inspect.expect("observe still scans");
    let ctx = inspector.context(&request, window, step.truncated);
    assert!(
        checks.evaluate(&ctx).is_some(),
        "observe mode must still detect — it just does not act",
    );
}
