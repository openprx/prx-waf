/// Notification system — channels, configuration CRUD, rate-limited dispatch.
///
/// Supported channels:
///   email   — SMTP via lettre (`config_json`: `smtp_host`, `smtp_port`, username, password, from, to)
///   webhook — HTTP POST via reqwest (`config_json`: url, secret, headers)
///   telegram — Telegram Bot API (`config_json`: `bot_token`, `chat_id`)
///
/// Event types: `attack_detected` | `cert_expiry` | `high_traffic` | `backend_down`
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use waf_storage::models::CreateNotificationConfig;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Rate-limit state (in-process) ───────────────────────────────────────────

/// Per `config_id` last-sent timestamp for rate limiting.
pub type NotifRateLimiter = Arc<DashMap<Uuid, chrono::DateTime<Utc>>>;

pub fn new_rate_limiter() -> NotifRateLimiter {
    Arc::new(DashMap::new())
}

fn is_rate_limited(rl: &NotifRateLimiter, id: Uuid) -> bool {
    rl.get(&id).is_some_and(|last| {
        let elapsed = Utc::now().signed_duration_since(*last);
        elapsed < chrono::Duration::minutes(5)
    })
}

fn mark_sent(rl: &NotifRateLimiter, id: Uuid) {
    rl.insert(id, Utc::now());
}

// ─── Notification channel trait ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPayload {
    pub event_type: String,
    pub host_code: Option<String>,
    pub title: String,
    pub message: String,
    pub timestamp: chrono::DateTime<Utc>,
}

#[async_trait::async_trait]
pub trait NotificationChannel: Send + Sync {
    async fn send(&self, payload: &NotificationPayload) -> anyhow::Result<()>;
    fn channel_type(&self) -> &'static str;
}

// ─── Webhook channel ──────────────────────────────────────────────────────────

pub struct WebhookChannel {
    pub url: String,
    pub secret: Option<String>,
    client: reqwest::Client,
}

impl WebhookChannel {
    pub fn new(url: String, secret: Option<String>) -> Self {
        Self {
            url,
            secret,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for WebhookChannel {
    fn channel_type(&self) -> &'static str {
        "webhook"
    }

    async fn send(&self, payload: &NotificationPayload) -> anyhow::Result<()> {
        let mut req = self.client.post(&self.url).json(payload);
        if let Some(s) = &self.secret {
            req = req.header("X-WAF-Secret", s.as_str());
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("webhook returned HTTP {}", resp.status());
        }
        Ok(())
    }
}

// ─── Telegram channel ─────────────────────────────────────────────────────────

pub struct TelegramChannel {
    pub bot_token: String,
    pub chat_id: String,
    client: reqwest::Client,
}

impl TelegramChannel {
    pub fn new(bot_token: String, chat_id: String) -> Self {
        Self {
            bot_token,
            chat_id,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl NotificationChannel for TelegramChannel {
    fn channel_type(&self) -> &'static str {
        "telegram"
    }

    async fn send(&self, payload: &NotificationPayload) -> anyhow::Result<()> {
        let bot_token = &self.bot_token;
        let url = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
        let text = format!("*{}*\n{}\n\n_{}_", payload.title, payload.message, payload.event_type);
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("telegram API returned HTTP {}", resp.status());
        }
        Ok(())
    }
}

// ─── Email channel ────────────────────────────────────────────────────────────

pub struct EmailChannel {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
}

#[async_trait::async_trait]
impl NotificationChannel for EmailChannel {
    fn channel_type(&self) -> &'static str {
        "email"
    }

    async fn send(&self, payload: &NotificationPayload) -> anyhow::Result<()> {
        use lettre::{
            AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::header::ContentType,
            transport::smtp::authentication::Credentials,
        };

        let from_addr: lettre::message::Mailbox = self.from.parse()?;
        let mut builder = Message::builder()
            .from(from_addr)
            .subject(&payload.title)
            .header(ContentType::TEXT_PLAIN);
        for to in &self.to {
            let to_addr: lettre::message::Mailbox = to.parse()?;
            builder = builder.to(to_addr);
        }
        let msg = builder.body(payload.message.clone())?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.smtp_host)
            .port(self.smtp_port)
            .credentials(creds)
            .build();

        transport.send(msg).await?;
        Ok(())
    }
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/// Build a channel from a `NotificationConfig`'s `config_json`.
pub fn build_channel(channel_type: &str, config: &serde_json::Value) -> anyhow::Result<Box<dyn NotificationChannel>> {
    match channel_type {
        "webhook" => {
            let url = config["url"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("webhook.url missing"))?
                .to_string();
            let secret = config["secret"].as_str().map(ToOwned::to_owned);
            Ok(Box::new(WebhookChannel::new(url, secret)))
        }
        "telegram" => {
            let token = config["bot_token"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("telegram.bot_token missing"))?
                .to_string();
            let chat_id = config["chat_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("telegram.chat_id missing"))?
                .to_string();
            Ok(Box::new(TelegramChannel::new(token, chat_id)))
        }
        "email" => {
            let smtp_host = config["smtp_host"].as_str().unwrap_or("127.0.0.1").to_string();
            #[allow(clippy::cast_possible_truncation)]
            let smtp_port = config["smtp_port"].as_u64().unwrap_or(25) as u16;
            let username = config["username"].as_str().unwrap_or("").to_string();
            let password = config["password"].as_str().unwrap_or("").to_string();
            let from = config["from"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("email.from missing"))?
                .to_string();
            let to: Vec<String> = config["to"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(ToOwned::to_owned)).collect())
                .unwrap_or_default();
            Ok(Box::new(EmailChannel {
                smtp_host,
                smtp_port,
                username,
                password,
                from,
                to,
            }))
        }
        other => anyhow::bail!("unknown channel type: {other}"),
    }
}

/// Dispatch a notification event to all matching enabled configs.
/// This is fire-and-forget; errors are logged but not propagated.
pub async fn dispatch_notification(
    state: Arc<AppState>,
    event_type: String,
    host_code: Option<String>,
    title: String,
    message: String,
) {
    let payload = NotificationPayload {
        event_type: event_type.clone(),
        host_code: host_code.clone(),
        title,
        message,
        timestamp: Utc::now(),
    };

    let configs = match state.db.get_enabled_notification_configs(&event_type).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("notification dispatch: db error: {e}");
            return;
        }
    };

    for cfg in configs {
        // Check host_code filter: if config has a host_code, only dispatch for that host
        if let Some(h) = &cfg.host_code
            && host_code.as_deref() != Some(h.as_str())
        {
            continue;
        }

        if is_rate_limited(&state.notif_rate_limiter, cfg.id) {
            let _ = state
                .db
                .create_notification_log(Some(cfg.id), &event_type, &cfg.channel_type, "rate_limited", None, None)
                .await;
            continue;
        }

        match build_channel(&cfg.channel_type, &cfg.config_json) {
            Ok(chan) => match chan.send(&payload).await {
                Ok(()) => {
                    mark_sent(&state.notif_rate_limiter, cfg.id);
                    let _ = state
                        .db
                        .create_notification_log(
                            Some(cfg.id),
                            &event_type,
                            &cfg.channel_type,
                            "sent",
                            Some(&format!("{} sent", cfg.channel_type)),
                            None,
                        )
                        .await;
                    let _ = state.db.update_notification_last_triggered(cfg.id).await;
                }
                Err(e) => {
                    tracing::warn!("notification send error ({}): {e}", cfg.channel_type);
                    let _ = state
                        .db
                        .create_notification_log(
                            Some(cfg.id),
                            &event_type,
                            &cfg.channel_type,
                            "failed",
                            None,
                            Some(&e.to_string()),
                        )
                        .await;
                }
            },
            Err(e) => {
                tracing::warn!("notification build channel error: {e}");
            }
        }
    }
}

// ─── REST handlers ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HostFilter {
    pub host_code: Option<String>,
}

/// GET /api/notifications
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HostFilter>,
) -> ApiResult<Json<serde_json::Value>> {
    let rows = state.db.list_notification_configs(q.host_code.as_deref()).await?;
    Ok(Json(serde_json::json!({ "success": true, "data": rows })))
}

/// POST /api/notifications
pub async fn create_notification(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateNotificationConfig>,
) -> ApiResult<Json<serde_json::Value>> {
    // Validate channel type
    match req.channel_type.as_str() {
        "email" | "webhook" | "telegram" => {}
        other => {
            return Err(ApiError::BadRequest(format!("unknown channel_type: {other}")));
        }
    }
    let row = state.db.create_notification_config(req).await?;
    Ok(Json(serde_json::json!({ "success": true, "data": row })))
}

/// DELETE /api/notifications/:id
pub async fn delete_notification(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let deleted = state.db.delete_notification_config(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Notification config {id} not found")));
    }
    Ok(Json(serde_json::json!({ "success": true, "data": null })))
}

/// GET /api/notifications/log
pub async fn notification_log(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let rows = state.db.list_notification_log(100).await?;
    Ok(Json(serde_json::json!({ "success": true, "data": rows })))
}

/// POST /api/notifications/test  — send a test notification to a specific config
pub async fn test_notification(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let cfg = state
        .db
        .get_notification_config(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification config {id} not found")))?;

    let chan = build_channel(&cfg.channel_type, &cfg.config_json)
        .map_err(|e| ApiError::BadRequest(format!("channel config error: {e}")))?;

    let payload = NotificationPayload {
        event_type: "test".into(),
        host_code: cfg.host_code.clone(),
        title: "PRX-WAF Test Notification".into(),
        message: "This is a test notification from PRX-WAF.".into(),
        timestamp: Utc::now(),
    };

    chan.send(&payload).await.map_err(ApiError::Internal)?;

    Ok(Json(serde_json::json!({ "success": true, "data": "test sent" })))
}
