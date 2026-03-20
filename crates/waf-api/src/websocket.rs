/// WebSocket handlers for real-time event/log streaming.
///
/// Endpoints:
///   GET /ws/events?token=<jwt>  — live security events
///   GET /ws/logs?token=<jwt>    — live access log stream
///
/// Max 50 concurrent connections. Heartbeat ping every 30 s.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::{
    Json,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use tokio::time::interval;

use crate::auth::validate_access_token;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

const MAX_WS_CONNECTIONS: u32 = 50;

/// GET /ws/events — live security event stream
pub async fn ws_events(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    auth_and_upgrade(ws, params, state, "events").await
}

/// GET /ws/logs — live access log stream
pub async fn ws_logs(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    auth_and_upgrade(ws, params, state, "logs").await
}

async fn auth_and_upgrade(
    ws: WebSocketUpgrade,
    params: WsQuery,
    state: Arc<AppState>,
    stream: &'static str,
) -> Response {
    // Validate JWT from query param
    let token = match params.token {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "token required" })),
            )
                .into_response();
        }
    };

    if validate_access_token(&token, &state.jwt_secret).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid token" })),
        )
            .into_response();
    }

    // Check connection limit
    let current = state.ws_connections.fetch_add(1, Ordering::Relaxed);
    if current >= MAX_WS_CONNECTIONS {
        state.ws_connections.fetch_sub(1, Ordering::Relaxed);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "max connections reached" })),
        )
            .into_response();
    }

    let s = state.clone();
    ws.on_upgrade(move |socket| handle_ws(socket, s, stream))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>, stream: &'static str) {
    // Subscribe to the Database's real-time event broadcast channel
    let mut rx = state.db.subscribe_events();
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Forward broadcast events to this client
            msg = rx.recv() => {
                match msg {
                    Ok(val) => {
                        let text = val.to_string();
                        // For /ws/logs, forward all events; for /ws/events, forward security events
                        let send_it = match stream {
                            "logs"   => true,
                            _        => true, // all events by default
                        };
                        if send_it
                            && socket.send(Message::Text(text)).await.is_err() {
                                break;
                            }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Skip lagged messages
                        continue;
                    }
                    Err(_) => break,
                }
            }

            // Heartbeat ping
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }

            // Handle incoming messages (pong, close, etc.)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Pong(_))) => {},
                    _ => {}
                }
            }
        }
    }

    state.ws_connections.fetch_sub(1, Ordering::Relaxed);
}
