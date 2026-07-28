//! Per-request rule-hit audit log, in `ModSecurity` error-log shape.
//!
//! # Why a second log
//!
//! `security_events` answers "why was this request blocked": one row carrying
//! the single heaviest rule. That is the right shape for an alert and the wrong
//! shape for tuning. Tuning asks *which* rules a request touched and how much
//! each of them added — including for the requests that scored but stayed under
//! the threshold, which produce no row at all today because nothing was blocked.
//! Anomaly scoring made that gap load-bearing: a request can now match three
//! rules and be allowed, and the operator has no way to see it.
//!
//! This log records exactly that: one line per matched CRS rule, plus one line
//! for the anomaly-score verdict when the threshold is reached, in the bracketed
//! `[key "value"]` shape `ModSecurity` writes to the web server error log. The
//! shape is not decoration — it is what every existing CRS tool chain, `go-ftw`
//! included, already knows how to read.
//!
//! # Not on the request path
//!
//! The hot path formats the lines for one request into a single `String` and
//! `try_send`s it into a **bounded** channel; a single background task owns the
//! file and does every `write`. A full channel drops the block and increments a
//! counter that is logged periodically — the same degradation the semantic sink
//! chose (see [`crate::semantic_sink`]), for the same reason: an attack flood
//! must not be able to turn logging into back-pressure on traffic.
//!
//! One channel means one writer means FIFO: lines appear in the file in the
//! order the requests were inspected. The marker protocol below depends on that.
//!
//! # Markers
//!
//! When [`waf_common::AuditLogConfig::marker_header`] is set, a request carrying
//! that header contributes exactly one line — the header's value, echoed — and
//! **no** rule lines. That is the same trick the upstream CRS test container
//! plays with `CRS_ENABLE_TEST_MARKER=1`, which appends
//!
//! ```text
//! SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" \
//!     "id:999999,phase:1,pass,t:none,log,msg:'%{MATCHED_VAR}',ctl:ruleRemoveById=1-999999"
//! ```
//!
//! to `crs-setup.conf` (`coreruleset/modsecurity-crs-docker`,
//! `src/opt/modsecurity/configure-rules.sh`). `go-ftw`'s log mode brackets each
//! test stage between two such marker requests and reads only the lines between
//! them (`go-ftw/waflog/read.go`, `getMarkedLines`), so a marker request that
//! logged rules of its own would contaminate the very window it delimits.
//!
//! # PII and log injection
//!
//! Only request *metadata* is recorded — client IP, host, method, URI path —
//! which is the set `attack_logs` already persists. The query string is opt-in
//! ([`waf_common::AuditLogConfig::include_query`]) and the matched data is never
//! written. Every dynamic value goes through [`sanitize`] first: the URI, the
//! `Host` header and the marker value are all attacker-controlled, and a raw
//! newline or a literal `[id "941100"]` inside one of them would let a client
//! forge log lines and rule hits. Size-based rotation with a bounded number of
//! kept generations is what limits how long this metadata survives on disk.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use waf_common::metrics::{self, BudgetEvent};
use waf_common::{AuditLogConfig, RequestCtx};

/// Bounded channel capacity, in per-request blocks. A sustained flood beyond
/// this is dropped (and counted), never queued without limit.
const CHANNEL_CAPACITY: usize = 4096;

/// Max blocks drained per worker wake-up before the file is flushed.
const DRAIN_BATCH_SIZE: usize = 256;

/// How often the worker logs (and resets) the drop counter.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Longest a single sanitized value may be. Long enough for a real URI, short
/// enough that one request cannot write a megabyte of log.
const MAX_VALUE_LEN: usize = 512;

/// CRS's own id for "inbound anomaly score exceeded"
/// (`REQUEST-949-BLOCKING-EVALUATION.conf`). The threshold comparison in
/// [`crate::checks::OWASPCheck`] *is* that rule, so the verdict line carries its
/// id rather than inventing a private one.
const BLOCKING_EVALUATION_ID: u32 = 949_110;

/// The response-phase counterpart, `RESPONSE-959-BLOCKING-EVALUATION.conf` rule
/// `959100`. Upstream spells its message
/// `Outbound Anomaly Score Exceeded (Total Score: %{tx.blocking_outbound_anomaly_score})`,
/// and the CRS regression corpus asserts on that exact wording
/// (`RESPONSE-959-BLOCKING-EVALUATION/959100.yaml`, test 3 matches
/// `Outbound Anomaly Score Exceeded \(Total Score: `), so the text below is a
/// contract, not a phrasing choice.
const OUTBOUND_BLOCKING_EVALUATION_ID: u32 = 959_100;

/// One rule that matched, as the audit log needs it.
///
/// Borrowed on purpose: the caller already holds these strings on the compiled
/// rule and the line is formatted before anything is queued, so nothing here is
/// cloned to build a record that may then be dropped.
#[derive(Debug, Clone, Copy)]
pub struct RuleHit<'a> {
    /// The numeric upstream CRS id (`942100`), when the rule declares one.
    pub crs_id: Option<u32>,
    /// The engine's own rule identifier (`CRS-942100`).
    pub rule_ref: &'a str,
    /// Rule name / `msg`.
    pub name: &'a str,
    /// Severity label (`critical`, `error`, `warning`, `notice`).
    pub severity: &'a str,
    /// Anomaly score this rule contributed.
    pub score: u32,
}

/// Which CRS blocking-evaluation rule a [`ScoreVerdict`] stands for.
///
/// CRS keeps two independent accumulators and two independent thresholds — the
/// request one settled by `949110`, the response one by `959100` — so a verdict
/// line has to say which of them it is reporting. Collapsing the two onto one id
/// would make a response finding indistinguishable from a request finding to
/// every reader of this file, `go-ftw` included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScorePhase {
    /// Request phase (`REQUEST-949-BLOCKING-EVALUATION.conf`, id `949110`).
    #[default]
    Inbound,
    /// Response phase (`RESPONSE-959-BLOCKING-EVALUATION.conf`, id `959100`).
    Outbound,
}

impl ScorePhase {
    /// The upstream rule id that settles this phase's threshold comparison.
    const fn blocking_evaluation_id(self) -> u32 {
        match self {
            Self::Inbound => BLOCKING_EVALUATION_ID,
            Self::Outbound => OUTBOUND_BLOCKING_EVALUATION_ID,
        }
    }

    /// Upstream's `msg:` prefix for that rule, verbatim.
    const fn verdict_message(self) -> &'static str {
        match self {
            Self::Inbound => "Inbound Anomaly Score Exceeded",
            Self::Outbound => "Outbound Anomaly Score Exceeded",
        }
    }
}

/// The anomaly-score outcome for one request.
#[derive(Debug, Clone, Copy)]
pub struct ScoreVerdict {
    /// Accumulated anomaly score, in the phase named by [`Self::phase`].
    pub score: u32,
    /// Threshold the score was compared against.
    pub threshold: u32,
    /// Paranoia level the request was evaluated at.
    pub paranoia: u8,
    /// Whether the threshold was reached (i.e. `949110` / `959100` would fire
    /// upstream).
    pub reached_threshold: bool,
    /// Which accumulator this verdict reports.
    pub phase: ScorePhase,
}

/// Hot-path handle: one bounded sender plus a drop counter. Held by the engine
/// and shared with the OWASP check.
pub struct AuditLogSink {
    tx: mpsc::Sender<String>,
    /// Receiver, taken exactly once by [`Self::take_worker`].
    rx: parking_lot::Mutex<Option<mpsc::Receiver<String>>>,
    dropped: Arc<AtomicU64>,
    /// Lower-cased marker header name, or `None` when the marker protocol is off.
    marker_header: Option<String>,
    include_query: bool,
    path: PathBuf,
    max_size_bytes: Option<u64>,
    keep_rotations: u8,
}

/// The drain side, moved into the background task. Owns the file, so the hot
/// path never touches a file descriptor.
pub struct AuditLogWorker {
    rx: mpsc::Receiver<String>,
    dropped: Arc<AtomicU64>,
    path: PathBuf,
    max_size_bytes: Option<u64>,
    keep_rotations: u8,
    file: Option<tokio::fs::File>,
    written: u64,
}

impl AuditLogSink {
    /// Build a sink for an **enabled** configuration.
    ///
    /// Callers gate on [`waf_common::AuditLogConfig::enabled`]; a disabled log
    /// must not construct a sink at all, so that nothing is allocated and no
    /// task is started for the default configuration.
    #[must_use]
    pub fn new(cfg: &AuditLogConfig) -> Self {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            rx: parking_lot::Mutex::new(Some(rx)),
            dropped: Arc::new(AtomicU64::new(0)),
            marker_header: cfg.marker_header_lower(),
            include_query: cfg.include_query,
            path: PathBuf::from(cfg.path.clone()),
            max_size_bytes: cfg.max_size_bytes(),
            keep_rotations: cfg.keep_rotations,
        }
    }

    /// Take the worker (drain side) exactly once. Returns `None` on subsequent
    /// calls. The caller spawns [`AuditLogWorker::run`].
    #[must_use]
    pub fn take_worker(&self) -> Option<AuditLogWorker> {
        self.rx.lock().take().map(|rx| AuditLogWorker {
            rx,
            dropped: Arc::clone(&self.dropped),
            path: self.path.clone(),
            max_size_bytes: self.max_size_bytes,
            keep_rotations: self.keep_rotations,
            file: None,
            written: 0,
        })
    }

    /// The marker value carried by this request, if the marker protocol is on
    /// and the header is present.
    #[must_use]
    pub fn marker_of<'c>(&self, ctx: &'c RequestCtx) -> Option<&'c str> {
        let name = self.marker_header.as_deref()?;
        ctx.headers.get(name).map(String::as_str)
    }

    /// Record the marker line for a request that carries the marker header.
    ///
    /// A no-op for every other request, and for every request when the marker
    /// protocol is off. Called once per request, in the header phase, so the
    /// line lands in the file between the neighbouring requests' lines.
    pub fn record_marker(&self, ctx: &RequestCtx) {
        let Some(marker) = self.marker_of(ctx) else {
            return;
        };
        let Some(header) = self.marker_header.as_deref() else {
            return;
        };
        let line = format!(
            "{} prx-waf: Marker. [msg \"{}: {}\"] [unique_id \"{}\"]\n",
            timestamp(),
            sanitize(header),
            sanitize(marker),
            sanitize(&ctx.req_id),
        );
        self.enqueue(line);
    }

    /// Record the CRS rules that matched one request, plus the anomaly-score
    /// verdict.
    ///
    /// Suppressed for a request carrying the marker header: upstream's marker
    /// rule ends in `ctl:ruleRemoveById=1-999999` precisely so the marker
    /// request cannot contribute rule hits to the window it delimits.
    pub fn record_rule_hits(&self, ctx: &RequestCtx, hits: &[RuleHit<'_>], verdict: ScoreVerdict) {
        if hits.is_empty() && !verdict.reached_threshold {
            return;
        }
        if self.marker_of(ctx).is_some() {
            return;
        }

        let ts = timestamp();
        let client = sanitize(&ctx.client_ip.to_string());
        let host = sanitize(&ctx.host);
        let uri = sanitize(&self.uri_of(ctx));
        let req_id = sanitize(&ctx.req_id);

        // One allocation for the whole request; the worker writes it as one
        // `write_all`, so a request's lines can never be interleaved with
        // another request's.
        let mut block = String::with_capacity(hits.len().saturating_add(1).saturating_mul(192));
        for hit in hits {
            block.push_str(&ts);
            block.push_str(" prx-waf: Warning. CRS rule matched.");
            if let Some(id) = hit.crs_id {
                let _ = write!(block, " [id \"{id}\"]");
            }
            let _ = writeln!(
                block,
                " [ref \"{}\"] [msg \"{}\"] [severity \"{}\"] [score \"{}\"] [paranoia \"{}\"] \
                 [client {client}] [hostname \"{host}\"] [uri \"{uri}\"] [unique_id \"{req_id}\"]",
                sanitize(hit.rule_ref),
                sanitize(hit.name),
                sanitize(hit.severity),
                hit.score,
                verdict.paranoia,
            );
        }
        if verdict.reached_threshold {
            let _ = writeln!(
                block,
                "{ts} prx-waf: Access denied. [id \"{}\"] \
                 [msg \"{} (Total Score: {})\"] [score \"{}\"] \
                 [threshold \"{}\"] [paranoia \"{}\"] [client {client}] [hostname \"{host}\"] \
                 [uri \"{uri}\"] [unique_id \"{req_id}\"]",
                verdict.phase.blocking_evaluation_id(),
                verdict.phase.verdict_message(),
                verdict.score,
                verdict.score,
                verdict.threshold,
                verdict.paranoia,
            );
        }
        self.enqueue(block);
    }

    /// Number of blocks dropped because the channel was full (telemetry/tests).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The URI as it should be logged: path, plus the query only when the
    /// operator opted in.
    fn uri_of(&self, ctx: &RequestCtx) -> String {
        if self.include_query && !ctx.query.is_empty() {
            format!("{}?{}", ctx.path, ctx.query)
        } else {
            ctx.path.clone()
        }
    }

    /// Hot-path enqueue: synchronous, never awaits, never spawns.
    fn enqueue(&self, block: String) {
        if self.tx.try_send(block).is_err() {
            metrics::record_budget_event(BudgetEvent::AuditLogDrop);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AuditLogWorker {
    /// Everything queued so far, concatenated, without touching the filesystem.
    ///
    /// Test-only, and crate-visible so the checks that *feed* this log can
    /// assert on what came out of them without each of them re-implementing a
    /// drain. Not compiled into the shipped binary.
    #[cfg(test)]
    pub(crate) fn drain_to_string(&mut self) -> String {
        let mut out = String::new();
        while let Ok(block) = self.rx.try_recv() {
            out.push_str(&block);
        }
        out
    }

    /// Drain the channel in bounded batches, appending to the log file and
    /// rotating it when it outgrows the configured size.
    ///
    /// Exits when the channel closes (the engine, and therefore the last
    /// `Sender`, has been dropped), draining whatever is still queued first.
    pub async fn run(mut self) {
        let mut ticker = tokio::time::interval(DROP_LOG_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.log_and_reset_drops(),
                maybe = self.rx.recv() => {
                    let Some(first) = maybe else {
                        self.log_and_reset_drops();
                        return;
                    };
                    let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH_SIZE {
                        match self.rx.try_recv() {
                            Ok(block) => batch.push(block),
                            Err(_) => break,
                        }
                    }
                    for block in batch {
                        self.write_block(&block).await;
                    }
                    self.flush().await;
                }
            }
        }
    }

    /// Append one request's block, rotating first when the file is full.
    async fn write_block(&mut self, block: &str) {
        if self.file.is_none() {
            self.open().await;
        }
        if let Some(limit) = self.max_size_bytes
            && self.written >= limit
        {
            self.rotate().await;
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        if let Err(e) = file.write_all(block.as_bytes()).await {
            warn!("Audit log write failed ({}): {e}", self.path.display());
            // Drop the handle so the next block retries the open; a transient
            // ENOSPC or a rotated-away inode then recovers by itself.
            self.file = None;
            return;
        }
        self.written = self.written.saturating_add(block.len() as u64);
    }

    async fn flush(&mut self) {
        if let Some(file) = self.file.as_mut()
            && let Err(e) = file.flush().await
        {
            warn!("Audit log flush failed ({}): {e}", self.path.display());
        }
    }

    /// Open (or create) the live log file in append mode, creating the parent
    /// directory if it does not exist.
    async fn open(&mut self) {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            error!("Audit log directory {} could not be created: {e}", parent.display());
            return;
        }
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(file) => {
                self.written = match file.metadata().await {
                    Ok(meta) => meta.len(),
                    Err(e) => {
                        warn!("Audit log size unknown ({}): {e}", self.path.display());
                        0
                    }
                };
                self.file = Some(file);
            }
            Err(e) => error!("Audit log {} could not be opened: {e}", self.path.display()),
        }
    }

    /// Shift `<path>.N-1` to `<path>.N`, move the live file to `<path>.1` and
    /// reopen. The oldest generation is deleted, which is what bounds how long
    /// request metadata survives on disk.
    async fn rotate(&mut self) {
        self.file = None;
        self.written = 0;
        if self.keep_rotations == 0 {
            if let Err(e) = tokio::fs::remove_file(&self.path).await {
                warn!("Audit log {} could not be truncated: {e}", self.path.display());
            }
            self.open().await;
            return;
        }
        for generation in (1..=u32::from(self.keep_rotations)).rev() {
            let from = if generation == 1 {
                self.path.clone()
            } else {
                generation_path(&self.path, generation.saturating_sub(1))
            };
            let to = generation_path(&self.path, generation);
            if generation == u32::from(self.keep_rotations) {
                // Deleting the oldest first keeps the rename below from
                // silently overwriting it on platforms that refuse to.
                let _ = tokio::fs::remove_file(&to).await;
            }
            if tokio::fs::metadata(&from).await.is_ok()
                && let Err(e) = tokio::fs::rename(&from, &to).await
            {
                warn!("Audit log rotation {} -> {} failed: {e}", from.display(), to.display());
            }
        }
        self.open().await;
    }

    fn log_and_reset_drops(&self) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            warn!(dropped, "Audit log channel full — dropped records (back-pressure)");
        }
    }
}

/// `<path>.N`
fn generation_path(path: &Path, generation: u32) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{generation}"));
    PathBuf::from(name)
}

/// Spawn the drain worker on the current Tokio runtime, if one exists.
///
/// Returns `true` when the worker was started. Outside a runtime nothing is
/// started and the hot-path `try_send`s fill the channel and then drop — which
/// only matters when the log is enabled, and enabling it outside the async
/// server path is not a configuration that exists.
#[must_use]
pub fn spawn_worker_if_runtime(sink: &AuditLogSink) -> bool {
    let Some(worker) = sink.take_worker() else {
        return false;
    };
    let path = worker.path.clone();
    tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        handle.spawn(async move {
            info!("Audit log writer started: {}", path.display());
            worker.run().await;
        });
        true
    })
}

/// Current time as a bracketed ISO-8601 timestamp with microsecond precision.
///
/// Microseconds matter: `go-ftw` matches its markers by **whole-line equality**
/// (`waflog/read.go`, `getMarkedLines`), so two lines that differ only in their
/// content must not be allowed to collide, and a coarse timestamp makes
/// collisions likely under load.
fn timestamp() -> String {
    format!("[{}]", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ"))
}

/// Make an attacker-controlled value safe to put inside a `[key "value"]` field.
///
/// The URI, the `Host` header and the marker value all come from the client. A
/// newline would let a client append forged lines; a literal `[id "941100"]`
/// would let it forge a rule hit for any tool reading this file; a stray `"`
/// would break field parsing. Everything outside printable ASCII is replaced,
/// the bracket/quote characters are folded onto safe look-alikes, and the result
/// is truncated so one request cannot write an unbounded line.
fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(MAX_VALUE_LEN));
    for ch in value.chars() {
        if out.len() >= MAX_VALUE_LEN {
            out.push_str("...");
            break;
        }
        out.push(match ch {
            '"' => '\'',
            '[' => '(',
            ']' => ')',
            '\\' => '/',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '.',
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use waf_common::{HostConfig, RequestCtx};

    use super::*;

    fn ctx_with(headers: HashMap<String, String>) -> RequestCtx {
        RequestCtx {
            req_id: "req-1".to_owned(),
            client_ip: "127.0.0.1".parse().expect("literal IPv4 address"),
            client_port: 1234,
            method: "GET".to_owned(),
            host: "localhost".to_owned(),
            port: 80,
            path: "/get".to_owned(),
            query: "a=1".to_owned(),
            headers,
            body_preview: bytes::Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    fn enabled_config() -> AuditLogConfig {
        AuditLogConfig {
            enabled: true,
            marker_header: "X-CRS-Test".to_owned(),
            ..AuditLogConfig::default()
        }
    }

    fn drain(sink: &AuditLogSink) -> String {
        let mut worker = sink.take_worker().expect("worker taken once");
        let mut out = String::new();
        while let Ok(block) = worker.rx.try_recv() {
            out.push_str(&block);
        }
        out
    }

    fn hit() -> RuleHit<'static> {
        RuleHit {
            crs_id: Some(942_100),
            rule_ref: "CRS-942100",
            name: "SQL Injection Attack Detected via libinjection",
            severity: "critical",
            score: 5,
        }
    }

    const BELOW: ScoreVerdict = ScoreVerdict {
        score: 3,
        threshold: 5,
        paranoia: 1,
        reached_threshold: false,
        phase: ScorePhase::Inbound,
    };
    const REACHED: ScoreVerdict = ScoreVerdict {
        score: 5,
        threshold: 5,
        paranoia: 1,
        reached_threshold: true,
        phase: ScorePhase::Inbound,
    };
    /// The outbound counterpart of [`REACHED`]: one `ERROR` response rule (4)
    /// against the outbound threshold (4).
    const OUTBOUND_REACHED: ScoreVerdict = ScoreVerdict {
        score: 4,
        threshold: 4,
        paranoia: 1,
        reached_threshold: true,
        phase: ScorePhase::Outbound,
    };

    #[test]
    fn rule_hits_are_logged_in_modsecurity_id_shape() {
        let sink = AuditLogSink::new(&enabled_config());
        sink.record_rule_hits(&ctx_with(HashMap::new()), &[hit()], REACHED);
        let out = drain(&sink);
        assert!(out.contains("[id \"942100\"]"), "missing CRS id: {out}");
        assert!(out.contains("[id \"949110\"]"), "missing verdict line: {out}");
        assert!(out.contains("[uri \"/get\"]"), "query must not leak by default: {out}");
    }

    #[test]
    fn an_outbound_verdict_carries_959100_and_upstreams_wording() {
        // `RESPONSE-959-BLOCKING-EVALUATION/959100.yaml` test 3 asserts on this
        // line with `match_regex: 'Outbound Anomaly Score Exceeded \(Total Score: '`,
        // and test 1 on `expect_ids: [959100]`. Both are checked here so a
        // reworded verdict line fails in `cargo test` rather than in go-ftw.
        let sink = AuditLogSink::new(&enabled_config());
        sink.record_rule_hits(&ctx_with(HashMap::new()), &[hit()], OUTBOUND_REACHED);
        let out = drain(&sink);
        assert!(out.contains("[id \"959100\"]"), "missing outbound verdict id: {out}");
        assert!(
            out.contains("Outbound Anomaly Score Exceeded (Total Score: 4)"),
            "upstream wording changed: {out}"
        );
        assert!(!out.contains("949110"), "outbound verdict must not claim 949110: {out}");
    }

    #[test]
    fn a_request_that_scored_without_blocking_is_still_recorded() {
        let sink = AuditLogSink::new(&enabled_config());
        sink.record_rule_hits(&ctx_with(HashMap::new()), &[hit()], BELOW);
        let out = drain(&sink);
        assert!(out.contains("[id \"942100\"]"), "sub-threshold hit must be logged");
        assert!(!out.contains("[id \"949110\"]"), "nothing was blocked: {out}");
    }

    #[test]
    fn a_marker_request_contributes_only_its_marker_line() {
        let sink = AuditLogSink::new(&enabled_config());
        let mut headers = HashMap::new();
        headers.insert("x-crs-test".to_owned(), "abc-s".to_owned());
        let ctx = ctx_with(headers);
        sink.record_marker(&ctx);
        sink.record_rule_hits(&ctx, &[hit()], REACHED);
        let out = drain(&sink);
        assert_eq!(out.lines().count(), 1, "marker request must log one line: {out}");
        // Lower case: `RequestCtx.headers` is keyed by the canonical
        // lower-cased name, and go-ftw lower-cases both sides before matching
        // (`waflog/read.go`, `CheckLogForMarker`).
        assert!(out.contains("x-crs-test: abc-s"), "marker not echoed: {out}");
        assert!(!out.contains("942100"), "marker request must not log rule hits: {out}");
    }

    #[test]
    fn markers_are_off_unless_a_header_is_configured() {
        let sink = AuditLogSink::new(&AuditLogConfig {
            enabled: true,
            ..AuditLogConfig::default()
        });
        let mut headers = HashMap::new();
        headers.insert("x-crs-test".to_owned(), "abc-s".to_owned());
        let ctx = ctx_with(headers);
        sink.record_marker(&ctx);
        assert!(drain(&sink).is_empty());
    }

    #[test]
    fn the_query_string_is_opt_in() {
        let sink = AuditLogSink::new(&AuditLogConfig {
            enabled: true,
            include_query: true,
            ..AuditLogConfig::default()
        });
        sink.record_rule_hits(&ctx_with(HashMap::new()), &[hit()], BELOW);
        assert!(drain(&sink).contains("[uri \"/get?a=1\"]"));
    }

    #[test]
    fn a_forged_rule_id_in_the_uri_cannot_reach_the_log() {
        let sink = AuditLogSink::new(&enabled_config());
        let mut ctx = ctx_with(HashMap::new());
        ctx.path = "/x\n[id \"941100\"] forged".to_owned();
        sink.record_rule_hits(&ctx, &[hit()], BELOW);
        let out = drain(&sink);
        assert!(!out.contains("[id \"941100\"]"), "log injection: {out}");
        assert_eq!(out.lines().count(), 1, "newline injection: {out}");
    }

    #[test]
    fn nothing_is_recorded_for_a_request_that_matched_nothing() {
        let sink = AuditLogSink::new(&enabled_config());
        sink.record_rule_hits(&ctx_with(HashMap::new()), &[], BELOW);
        assert!(drain(&sink).is_empty());
    }

    #[test]
    fn a_full_channel_drops_and_counts_instead_of_blocking() {
        let sink = AuditLogSink::new(&enabled_config());
        let ctx = ctx_with(HashMap::new());
        for _ in 0..(CHANNEL_CAPACITY + 16) {
            sink.record_rule_hits(&ctx, &[hit()], BELOW);
        }
        assert!(sink.dropped() >= 16, "expected drops, got {}", sink.dropped());
    }

    #[tokio::test]
    async fn the_worker_appends_and_rotates() {
        let dir = std::env::temp_dir().join(format!("prx-waf-audit-{}", uuid::Uuid::new_v4()));
        let path = dir.join("audit.log");
        let cfg = AuditLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            max_size_mb: 0,
            keep_rotations: 1,
            ..AuditLogConfig::default()
        };
        let sink = AuditLogSink::new(&cfg);
        let mut worker = sink.take_worker().expect("worker taken once");
        worker.max_size_bytes = Some(200);

        let ctx = ctx_with(HashMap::new());
        for _ in 0..8 {
            sink.record_rule_hits(&ctx, &[hit()], REACHED);
        }
        drop(sink);
        worker.run().await;

        assert!(tokio::fs::metadata(&path).await.is_ok(), "live log missing");
        assert!(
            tokio::fs::metadata(generation_path(&path, 1)).await.is_ok(),
            "rotated generation missing"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
