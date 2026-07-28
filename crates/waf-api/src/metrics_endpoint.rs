//! The Prometheus scrape endpoint.
//!
//! # Why this is its own listener and not a route on the management API
//!
//! The management API is behind a JWT and, optionally, an IP allowlist. A
//! Prometheus server has no good way to carry a JWT, so putting `/metrics`
//! there would push operators into configuring the *admin* token — the one that
//! can rewrite WAF rules, upload WASM plugins and replace TLS certificates — as
//! a scrape credential, stored in the monitoring system's config and copied
//! into every relabel debug session. A separate loopback listener with no
//! credential at all is a strictly smaller blast radius than a correct
//! credential in the wrong place.
//!
//! The endpoint is therefore **unauthenticated by design**, and its safety
//! comes entirely from the bind address. `[metrics] listen_addr` defaults to
//! `127.0.0.1:9127`; widening it publishes per-host request volumes, block
//! rates and detection counts, which is a reconnaissance surface. The startup
//! broadcast in `prx-waf` says so out loud when the bind is not loopback.
//!
//! It is deliberately not the same axum `Router` as the admin API: sharing one
//! would put the metrics handler behind that router's `DefaultBodyLimit`, CORS
//! layer, security-header layer and rate limiter, none of which mean anything
//! for a scrape, and would make a future admin-API middleware change able to
//! break monitoring.

use std::net::SocketAddr;

use anyhow::Context as _;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tracing::{error, info};

/// Content type Prometheus expects from a text-format scrape.
const TEXT_FORMAT: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Render the exposition.
///
/// Three outcomes, all of which a scraper can act on:
///
/// * metrics disabled — 404, because the listener should not exist at all in
///   that case and a 404 is the honest answer if one somehow does;
/// * encoding failed — 500 and a log line. Formatting into a `String` cannot
///   fail for any input this module produces, but the fallible signature is the
///   library's and swallowing it would be the kind of silent hole this whole
///   task exists to close;
/// * otherwise the text.
async fn scrape() -> Response {
    match waf_common::metrics::encode() {
        Some(Ok(body)) => ([(header::CONTENT_TYPE, TEXT_FORMAT)], body).into_response(),
        Some(Err(e)) => {
            error!("Metrics exposition failed to encode: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed").into_response()
        }
        None => (StatusCode::NOT_FOUND, "metrics are disabled").into_response(),
    }
}

/// The router this listener serves: `/metrics`, and nothing else.
///
/// `/` answers too, with a pointer, because someone will open the port in a
/// browser and an empty 404 tells them nothing about which process they found.
pub fn build_router() -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .route("/", get(|| async { "prx-waf metrics — scrape /metrics\n" }))
}

/// Bind `listen_addr` and serve the exposition until the process exits.
///
/// Returns an error rather than exiting the process if the bind fails: a
/// metrics port that is already taken must not stop a WAF from filtering
/// traffic. The caller logs it.
///
/// The three failures are given separate context because they need separate
/// fixes and the bare `io::Error` does not distinguish them: a malformed
/// `listen_addr` is a config typo, a refused bind is almost always another
/// process on the port, and a failure after that is the accept loop dying.
pub async fn serve(listen_addr: &str) -> anyhow::Result<()> {
    let addr: SocketAddr = listen_addr
        .parse()
        .with_context(|| format!("[metrics] listen_addr = {listen_addr:?} is not an ip:port address"))?;
    let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| {
        format!("cannot bind the metrics listener on {addr} — the port is most likely already taken")
    })?;
    info!("Metrics endpoint listening on http://{addr}/metrics");
    axum::serve(listener, build_router())
        .await
        .with_context(|| format!("the metrics listener on {addr} stopped serving"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// With metrics off the endpoint must say so rather than returning an empty
    /// body a scraper would read as "zero traffic".
    #[tokio::test]
    async fn scrape_reports_disabled_when_metrics_are_off() {
        // `waf_common::metrics::init` is process-global and other tests in this
        // binary do not call it, so this exercises the disabled path.
        if waf_common::metrics::enabled() {
            return;
        }
        let response = build_router()
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// A typo in `listen_addr` must name the setting it came from. `AddrParseError`
    /// renders as "invalid socket address syntax" and says nothing else.
    #[tokio::test]
    async fn unparseable_listen_addr_names_the_setting() {
        let err = serve("127.0.0.1")
            .await
            .expect_err("a bare IP is not an ip:port address");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("[metrics] listen_addr"), "{rendered}");
    }

    /// The failure operators actually hit. The OS says "address in use"; the log
    /// has to say which listener could not start.
    #[tokio::test]
    async fn taken_port_says_it_is_the_metrics_listener() {
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("an ephemeral loopback port is always available");
        let addr = squatter.local_addr().expect("a bound listener has an address");
        let err = serve(&addr.to_string())
            .await
            .expect_err("the port is held by this test");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("cannot bind the metrics listener"), "{rendered}");
        assert!(rendered.contains(&addr.to_string()), "{rendered}");
    }

    #[tokio::test]
    async fn root_points_at_the_scrape_path() {
        let response = build_router()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
