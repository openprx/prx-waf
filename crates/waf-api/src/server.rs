use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{login, logout, refresh_token};
use crate::cache_api::{cache_flush, cache_flush_host, cache_flush_key, cache_stats};
use crate::crowdsec::{
    crowdsec_stats, crowdsec_status, delete_crowdsec_decision, get_crowdsec_config,
    list_crowdsec_decisions, list_crowdsec_events, test_crowdsec_connection,
    update_crowdsec_config,
};
use crate::handlers::*;
use crate::health::health_check;
use crate::middleware::require_auth;
use crate::notifications::{
    create_notification, delete_notification, list_notifications, notification_log,
    test_notification,
};
use crate::plugins::{delete_plugin, disable_plugin, enable_plugin, list_plugins, upload_plugin};
use crate::security::{list_audit_log, security_headers_middleware};
use crate::state::AppState;
use crate::stats::{stats_overview, stats_timeseries};
use crate::static_files::static_handler;
use crate::tunnels::{create_tunnel, delete_tunnel, list_tunnels, ws_tunnel};
use crate::websocket::{ws_events, ws_logs};

/// Build the Axum router with all API routes
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no JWT)
    let public_routes = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/refresh", post(refresh_token))
        .route("/health", get(health_check));

    // Protected API routes (JWT required)
    let protected_routes = Router::new()
        // Hosts
        .route("/api/hosts", get(list_hosts).post(create_host))
        .route("/api/hosts/:id", get(get_host).put(update_host).delete(delete_host))
        // Allow IPs
        .route("/api/allow-ips", get(list_allow_ips).post(create_allow_ip))
        .route("/api/allow-ips/:id", delete(delete_allow_ip))
        // Block IPs
        .route("/api/block-ips", get(list_block_ips).post(create_block_ip))
        .route("/api/block-ips/:id", delete(delete_block_ip))
        // Allow URLs
        .route("/api/allow-urls", get(list_allow_urls).post(create_allow_url))
        .route("/api/allow-urls/:id", delete(delete_allow_url))
        // Block URLs
        .route("/api/block-urls", get(list_block_urls).post(create_block_url))
        .route("/api/block-urls/:id", delete(delete_block_url))
        // Attack logs
        .route("/api/attack-logs", get(list_attack_logs))
        // Security events
        .route("/api/security-events", get(list_security_events))
        // System status
        .route("/api/status", get(get_status))
        // Rule reload
        .route("/api/reload", post(reload_rules))
        // Phase 3: Custom rules
        .route("/api/custom-rules", get(list_custom_rules).post(create_custom_rule))
        .route("/api/custom-rules/:id", delete(delete_custom_rule))
        // Phase 3: Sensitive patterns
        .route("/api/sensitive-patterns", get(list_sensitive_patterns).post(create_sensitive_pattern))
        .route("/api/sensitive-patterns/:id", delete(delete_sensitive_pattern))
        // Phase 3: Hotlink config
        .route("/api/hotlink-config", get(get_hotlink_config).post(upsert_hotlink_config))
        // Phase 3: LB backends
        .route("/api/lb-backends", get(list_lb_backends).post(create_lb_backend))
        .route("/api/lb-backends/:id", delete(delete_lb_backend))
        // Phase 3: Certificates
        .route("/api/certificates", get(list_certificates).post(upload_certificate))
        .route("/api/certificates/:id", delete(delete_certificate))
        // Phase 4: Statistics
        .route("/api/stats/overview", get(stats_overview))
        .route("/api/stats/timeseries", get(stats_timeseries))
        // Phase 4: Notifications
        .route("/api/notifications", get(list_notifications).post(create_notification))
        .route("/api/notifications/:id", delete(delete_notification))
        .route("/api/notifications/log", get(notification_log))
        .route("/api/notifications/:id/test", post(test_notification))
        // Phase 5: WASM Plugins
        .route("/api/plugins", get(list_plugins).post(upload_plugin))
        .route("/api/plugins/:id", delete(delete_plugin))
        .route("/api/plugins/:id/enable", post(enable_plugin))
        .route("/api/plugins/:id/disable", post(disable_plugin))
        // Phase 5: Tunnels
        .route("/api/tunnels", get(list_tunnels).post(create_tunnel))
        .route("/api/tunnels/:id", delete(delete_tunnel))
        // Phase 5: Cache
        .route("/api/cache/stats", get(cache_stats))
        .route("/api/cache", delete(cache_flush))
        .route("/api/cache/host/:host", delete(cache_flush_host))
        .route("/api/cache/key", delete(cache_flush_key))
        // Phase 5: Audit log
        .route("/api/audit-log", get(list_audit_log))
        // Phase 6: CrowdSec
        .route("/api/crowdsec/status", get(crowdsec_status))
        .route("/api/crowdsec/decisions", get(list_crowdsec_decisions))
        .route("/api/crowdsec/decisions/:id", delete(delete_crowdsec_decision))
        .route("/api/crowdsec/test", post(test_crowdsec_connection))
        .route("/api/crowdsec/config", get(get_crowdsec_config).put(update_crowdsec_config))
        .route("/api/crowdsec/stats", get(crowdsec_stats))
        .route("/api/crowdsec/events", get(list_crowdsec_events))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // WebSocket routes (auth via query param, no layer middleware)
    let ws_routes = Router::new()
        .route("/ws/events", get(ws_events))
        .route("/ws/logs", get(ws_logs))
        .route("/ws/tunnel", get(ws_tunnel));

    // Serve the embedded Vue 3 admin UI at /ui/*
    let ui_routes = Router::new()
        .route("/ui", get(static_handler))
        .route("/ui/", get(static_handler))
        .route("/ui/*path", get(static_handler));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(ws_routes)
        .merge(ui_routes)
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start the management API server
pub async fn start_api_server(
    listen_addr: &str,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = listen_addr.parse()?;
    let app = build_router(state);

    info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
