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

use anyhow::Context as _;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;
use waf_storage::models::{CreateNotificationConfig, NotificationConfig, UpdateNotificationConfig};

use waf_common::crypto::{decrypt_field, encrypt_field, master_key};
use waf_common::url_validator::validate_public_url_with_ips;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Rate-limit state (in-process) ───────────────────────────────────────────

/// Rate-limit bucket identity: one bucket per (config, host).
///
/// Keying on the config alone would mean a flood against one host silences
/// alerts for every other host sharing a channel — an operator watching ten
/// sites through one webhook would hear about the first one attacked and
/// nothing else. The host is therefore part of the key.
pub type NotifRateLimitKey = (Uuid, Option<String>);

/// Per-(config, host) last-sent timestamp for rate limiting.
pub type NotifRateLimiter = Arc<DashMap<NotifRateLimitKey, chrono::DateTime<Utc>>>;

/// Cap on live rate-limit buckets before stale ones are swept.
///
/// Bucket keys come from configured hosts, so this is a defensive bound rather
/// than an expected one: it guarantees the map cannot grow without limit even
/// if a future producer starts deriving `host_code` from request data.
const MAX_RATE_LIMIT_ENTRIES: usize = 4096;

/// Age at which a bucket is considered stale and swept.
const RATE_LIMIT_ENTRY_TTL: chrono::TimeDelta = chrono::TimeDelta::hours(24);

pub fn new_rate_limiter() -> NotifRateLimiter {
    Arc::new(DashMap::new())
}

/// Whether this (config, host) bucket is still inside its cooldown.
///
/// `window_secs` is the channel's own `rate_limit_secs`; `0` (or negative)
/// disables the cooldown for that channel.
fn is_rate_limited(rl: &NotifRateLimiter, key: &NotifRateLimitKey, window_secs: i64) -> bool {
    if window_secs <= 0 {
        return false;
    }
    let Some(window) = chrono::TimeDelta::try_seconds(window_secs) else {
        // Only reachable for an absurd stored value; treat it as "no cooldown"
        // rather than silently muting the channel forever.
        return false;
    };
    rl.get(key)
        .is_some_and(|last| Utc::now().signed_duration_since(*last) < window)
}

fn mark_sent(rl: &NotifRateLimiter, key: NotifRateLimitKey) {
    rl.insert(key, Utc::now());
    if rl.len() > MAX_RATE_LIMIT_ENTRIES {
        let cutoff = Utc::now() - RATE_LIMIT_ENTRY_TTL;
        rl.retain(|_, last| *last > cutoff);
    }
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
    /// Construct a webhook channel with DNS-rebinding protection.
    ///
    /// `host` is the hostname extracted from the already-validated URL
    /// (obtained from `validated_url.host_str()`).  `resolved_addrs` must be
    /// the addresses returned by [`validate_public_url_with_ips`] at validation
    /// time.  When both `host` and `resolved_addrs` are non-empty (i.e. the URL
    /// contains a DNS hostname rather than an IP literal), the reqwest client is
    /// configured via `resolve_to_addrs` to connect only to those IPs.
    ///
    /// This prevents DNS rebinding from redirecting a later request to a
    /// private/internal address between validation and send time (TOCTOU).
    ///
    /// Redirects are unconditionally disabled so a `3xx` response cannot
    /// point the client to an internal endpoint.
    pub fn new(
        url: String,
        secret: Option<String>,
        host: Option<&str>,
        resolved_addrs: &[std::net::SocketAddr],
    ) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Disable all redirects — a 3xx to an internal host would bypass
            // the SSRF check performed before construction.
            .redirect(reqwest::redirect::Policy::none());

        // Pin the client to the IPs that were validated at config-save time.
        // This closes the TOCTOU window between `validate_public_url_with_ips`
        // and the actual HTTP request: even if the attacker flips DNS to point
        // at 127.0.0.1 after validation, the pinned client will still connect
        // to the originally-resolved public IP.
        //
        // Only applied for DNS hostnames; IP-literal URLs return an empty
        // `resolved_addrs` slice and need no override.
        if !resolved_addrs.is_empty()
            && let Some(h) = host
        {
            builder = builder.resolve_to_addrs(h, resolved_addrs);
        }

        let client = builder.build().context("failed to build webhook HTTP client")?;
        Ok(Self { url, secret, client })
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
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("webhook request failed: {}", transport_failure(&e)))?;
        if !resp.status().is_success() {
            anyhow::bail!("webhook returned HTTP {}", resp.status());
        }
        Ok(())
    }
}

/// Describe a transport failure without echoing the request URL.
///
/// `reqwest`'s `Display` embeds the full request URL. For Telegram that URL
/// contains the bot token, and for many webhook providers (Slack, Discord, …)
/// the URL *is* the shared secret. These strings are persisted to
/// `notification_log` and rendered in the admin UI, so only the failure class
/// is reported; the full error stays in the process log.
fn transport_failure(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_decode() {
        "malformed response"
    } else if e.is_body() {
        "request body error"
    } else {
        "transport error"
    }
}

// ─── Telegram channel ─────────────────────────────────────────────────────────

pub struct TelegramChannel {
    pub bot_token: String,
    pub chat_id: String,
    client: reqwest::Client,
}

impl TelegramChannel {
    pub fn new(bot_token: String, chat_id: String) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build Telegram HTTP client")?;
        Ok(Self {
            bot_token,
            chat_id,
            client,
        })
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
        // The URL carries the bot token — never let the error text repeat it.
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("telegram request failed: {}", transport_failure(&e)))?;
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

// ─── Secret handling inside `config_json` ─────────────────────────────────────

/// Object key marking an encrypted secret inside `config_json`.
///
/// A secret member is persisted as `{"$enc": "<base64 ciphertext>"}` rather than
/// as a bare string. Because the wrapper is an object it can never be confused
/// with a legacy plaintext value (always a JSON string), which is what makes the
/// read-time backward-compatibility path unambiguous.
const ENC_KEY: &str = "$enc";

/// Stand-in emitted for secret values that are structurally visible in API
/// output (currently webhook header values, whose names are kept).
const SECRET_MASK: &str = "***";

/// A member of `config_json` that holds a credential.
#[derive(Debug, Clone, Copy)]
enum SecretField {
    /// A top-level string member (e.g. `password`).
    Value(&'static str),
    /// A top-level object whose every value is a credential — webhook
    /// `headers` routinely carries `Authorization`.
    ObjectValues(&'static str),
}

impl SecretField {
    const fn name(self) -> &'static str {
        match self {
            Self::Value(n) | Self::ObjectValues(n) => n,
        }
    }
}

/// Credential members per channel type. Everything not listed here is treated
/// as non-secret configuration (endpoint, recipients, port, …).
fn secret_fields(channel_type: &str) -> &'static [SecretField] {
    match channel_type {
        "email" => &[SecretField::Value("password")],
        "webhook" => &[SecretField::Value("secret"), SecretField::ObjectValues("headers")],
        "telegram" => &[SecretField::Value("bot_token")],
        _ => &[],
    }
}

/// Master key holder that reads (and validates) `MASTER_KEY` on first use, so a
/// config without secrets still works on deployments that never set it.
struct LazyMasterKey(Option<[u8; 32]>);

impl LazyMasterKey {
    const fn new() -> Self {
        Self(None)
    }

    /// A holder pre-seeded with an explicit key, so the encryption paths can be
    /// exercised without touching process-global environment state.
    #[cfg(test)]
    const fn with_key(key: [u8; 32]) -> Self {
        Self(Some(key))
    }

    fn get(&mut self) -> anyhow::Result<[u8; 32]> {
        if let Some(k) = self.0 {
            return Ok(k);
        }
        let k = master_key()?;
        self.0 = Some(k);
        Ok(k)
    }
}

/// Ciphertext carried by an encrypted-secret wrapper, if `v` is one.
fn enc_ciphertext(v: &Value) -> Option<&str> {
    v.as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get(ENC_KEY))
        .and_then(Value::as_str)
}

fn enc_wrapper(ciphertext: String) -> Value {
    let mut o = Map::new();
    o.insert(ENC_KEY.to_owned(), Value::String(ciphertext));
    Value::Object(o)
}

/// Decide what to persist for a single secret member.
///
/// Returns `None` when the caller supplied nothing and nothing is stored.
fn resolve_secret(
    incoming: Option<&Value>,
    stored: Option<&Value>,
    key: &mut LazyMasterKey,
) -> anyhow::Result<Option<Value>> {
    match incoming {
        // A fresh secret from the caller: encrypt it.
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(enc_wrapper(encrypt_field(&key.get()?, s)?))),
        // A ciphertext echoed back unchanged: keep it verbatim (idempotent save).
        Some(v) if enc_ciphertext(v).is_some() => Ok(Some(v.clone())),
        // Absent, null, or empty string → keep whatever is already stored.
        // This is what lets an admin edit a config without re-typing secrets.
        _ => match stored {
            // Legacy plaintext from a row written before encryption at rest:
            // upgrade it to ciphertext as part of this write.
            Some(Value::String(s)) if !s.is_empty() => Ok(Some(enc_wrapper(encrypt_field(&key.get()?, s)?))),
            other => Ok(other.cloned()),
        },
    }
}

/// Build the `config_json` to persist.
///
/// Non-secret members are taken verbatim from `incoming`; secret members are
/// encrypted with `MASTER_KEY`, and secrets the caller left blank fall back to
/// the value already stored in `existing`. Saving an existing row therefore also
/// upgrades any legacy plaintext secret to ciphertext.
pub fn prepare_config_for_storage(
    channel_type: &str,
    incoming: &Value,
    existing: Option<&Value>,
) -> anyhow::Result<Value> {
    prepare_config_with_key(channel_type, incoming, existing, &mut LazyMasterKey::new())
}

fn prepare_config_with_key(
    channel_type: &str,
    incoming: &Value,
    existing: Option<&Value>,
    key: &mut LazyMasterKey,
) -> anyhow::Result<Value> {
    let mut out = incoming
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("config_json must be a JSON object"))?;

    for field in secret_fields(channel_type) {
        let name = field.name();
        let stored = existing.and_then(|e| e.get(name));
        let resolved = match *field {
            SecretField::Value(_) => resolve_secret(out.get(name), stored, key)?,
            SecretField::ObjectValues(_) => match out.get(name) {
                // Members are replaced wholesale; an empty value for a given
                // member keeps the stored value for that member only.
                Some(Value::Object(incoming_map)) => {
                    let mut merged = Map::new();
                    for (k, v) in incoming_map {
                        if let Some(value) = resolve_secret(Some(v), stored.and_then(|s| s.get(k)), key)? {
                            merged.insert(k.clone(), value);
                        }
                    }
                    Some(Value::Object(merged))
                }
                // Absent or blank → keep what is stored.
                _ => stored.cloned(),
            },
        };
        out.remove(name);
        if let Some(v) = resolved {
            out.insert(name.to_owned(), v);
        }
    }

    Ok(Value::Object(out))
}

/// Decrypt the secret members of a stored `config_json` so a channel can be
/// built from it.
///
/// Rows written before encryption-at-rest was introduced hold bare strings;
/// they are passed through unchanged so existing configs keep working, and the
/// next save re-persists them encrypted.
pub fn decrypt_config_for_use(channel_type: &str, stored: &Value) -> anyhow::Result<Value> {
    decrypt_config_with_key(channel_type, stored, &mut LazyMasterKey::new())
}

fn decrypt_config_with_key(channel_type: &str, stored: &Value, key: &mut LazyMasterKey) -> anyhow::Result<Value> {
    let mut out = stored
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("config_json must be a JSON object"))?;

    for field in secret_fields(channel_type) {
        let name = field.name();
        match *field {
            SecretField::Value(_) => {
                let ct = out.get(name).and_then(enc_ciphertext).map(ToOwned::to_owned);
                if let Some(ct) = ct {
                    let plain = decrypt_field(&key.get()?, &ct)
                        .with_context(|| format!("failed to decrypt {channel_type}.{name}"))?;
                    out.insert(name.to_owned(), Value::String(plain));
                }
            }
            SecretField::ObjectValues(_) => {
                let members: Vec<(String, String)> = out
                    .get(name)
                    .and_then(Value::as_object)
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| enc_ciphertext(v).map(|ct| (k.clone(), ct.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default();
                for (k, ct) in members {
                    let plain = decrypt_field(&key.get()?, &ct)
                        .with_context(|| format!("failed to decrypt {channel_type}.{name}.{k}"))?;
                    if let Some(map) = out.get_mut(name).and_then(Value::as_object_mut) {
                        map.insert(k, Value::String(plain));
                    }
                }
            }
        }
    }

    Ok(Value::Object(out))
}

/// Strip credentials from a stored `config_json` for API output.
///
/// Mirrors the `CrowdSec` config endpoint: the secret itself never leaves the
/// server, and a `<field>_set` boolean tells the UI whether one is configured.
fn redact_config(channel_type: &str, stored: &Value) -> Value {
    let mut out = stored.as_object().cloned().unwrap_or_default();

    for field in secret_fields(channel_type) {
        let name = field.name();
        match *field {
            SecretField::Value(_) => {
                let present = out.remove(name).is_some_and(|v| !v.is_null());
                out.insert(format!("{name}_set"), Value::Bool(present));
            }
            SecretField::ObjectValues(_) => {
                // Keep the member names — they identify the integration and are
                // not themselves credentials — but never the values.
                let masked: Option<Map<String, Value>> = out.get(name).and_then(Value::as_object).map(|m| {
                    m.keys()
                        .map(|k| (k.clone(), Value::String(SECRET_MASK.to_owned())))
                        .collect()
                });
                let present = masked.as_ref().is_some_and(|m| !m.is_empty());
                out.remove(name);
                if let Some(m) = masked {
                    out.insert(name.to_owned(), Value::Object(m));
                }
                out.insert(format!("{name}_set"), Value::Bool(present));
            }
        }
    }

    Value::Object(out)
}

/// API projection of a notification config: everything except the credentials.
#[derive(Debug, Clone, Serialize)]
pub struct NotificationConfigView {
    pub id: Uuid,
    pub name: String,
    pub host_code: Option<String>,
    pub event_type: String,
    pub channel_type: String,
    /// Channel settings with every credential removed or masked.
    pub config_json: Value,
    pub enabled: bool,
    pub rate_limit_secs: i32,
    pub last_triggered: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

impl From<&NotificationConfig> for NotificationConfigView {
    fn from(row: &NotificationConfig) -> Self {
        Self {
            id: row.id,
            name: row.name.clone(),
            host_code: row.host_code.clone(),
            event_type: row.event_type.clone(),
            channel_type: row.channel_type.clone(),
            config_json: redact_config(&row.channel_type, &row.config_json),
            enabled: row.enabled,
            rate_limit_secs: row.rate_limit_secs,
            last_triggered: row.last_triggered,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

/// Build a channel from a decrypted `config_json`.
///
/// Callers must pass the output of [`decrypt_config_for_use`], never the raw
/// stored value.
pub fn build_channel(channel_type: &str, config: &serde_json::Value) -> anyhow::Result<Box<dyn NotificationChannel>> {
    match channel_type {
        "webhook" => {
            let raw_url = config["url"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("webhook.url missing"))?;
            // SSRF guard: reject private/loopback IPs, reserved ranges, and
            // dangerous hostname literals.  Returns the resolved IPs so we can
            // pin the HTTP client and close the DNS-rebinding TOCTOU window.
            let (validated_url, resolved_addrs) =
                validate_public_url_with_ips(raw_url).map_err(|e| anyhow::anyhow!("webhook URL rejected: {e}"))?;
            // Extract the hostname from the already-validated URL so that
            // WebhookChannel::new() can call resolve_to_addrs without needing
            // to re-parse the URL string.
            let host = validated_url.host_str().map(ToOwned::to_owned);
            let secret = config["secret"].as_str().map(ToOwned::to_owned);
            Ok(Box::new(WebhookChannel::new(
                raw_url.to_string(),
                secret,
                host.as_deref(),
                &resolved_addrs,
            )?))
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
            // Telegram channel constructs its own URL from the bot token; the
            // URL is always https://api.telegram.org/... and is not user-controlled.
            Ok(Box::new(TelegramChannel::new(token, chat_id)?))
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
///
/// Callers reach this through [`crate::notify_runtime`], which coalesces bursts
/// so a flood of identical events becomes one call plus a summary. The
/// per-channel cooldown enforced here is the second, independent limiter: it
/// honours each channel's stored `rate_limit_secs` and is keyed per (config,
/// host), so one noisy host cannot mute the rest.
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

        let rl_key: NotifRateLimitKey = (cfg.id, host_code.clone());
        if is_rate_limited(&state.notif_rate_limiter, &rl_key, i64::from(cfg.rate_limit_secs)) {
            // Suppression is never silent: it lands in `notification_log` (the
            // admin UI renders it) *and* in the process log.
            tracing::info!(
                config = %cfg.name,
                channel = %cfg.channel_type,
                event_type = %event_type,
                host_code = host_code.as_deref().unwrap_or("-"),
                rate_limit_secs = cfg.rate_limit_secs,
                "notification suppressed by per-channel rate limit"
            );
            if let Err(e) = state
                .db
                .create_notification_log(
                    Some(cfg.id),
                    &event_type,
                    &cfg.channel_type,
                    "rate_limited",
                    Some(&format!("suppressed: within {}s cooldown", cfg.rate_limit_secs)),
                    None,
                )
                .await
            {
                tracing::warn!("failed to record rate_limited notification log: {e}");
            }
            continue;
        }

        // Secrets are stored encrypted; decrypt just before use. The error path
        // carries no plaintext, so it is safe to log.
        let plain_cfg = match decrypt_config_for_use(&cfg.channel_type, &cfg.config_json) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("notification config decrypt error ({}): {e}", cfg.channel_type);
                continue;
            }
        };

        match build_channel(&cfg.channel_type, &plain_cfg) {
            Ok(chan) => match chan.send(&payload).await {
                Ok(()) => {
                    mark_sent(&state.notif_rate_limiter, rl_key);
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
///
/// Credentials are never returned: each config is projected through
/// [`NotificationConfigView`], which redacts the secret members.
pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HostFilter>,
) -> ApiResult<Json<serde_json::Value>> {
    let rows = state.db.list_notification_configs(q.host_code.as_deref()).await?;
    let data: Vec<NotificationConfigView> = rows.iter().map(NotificationConfigView::from).collect();
    Ok(Json(serde_json::json!({ "success": true, "data": data })))
}

/// POST /api/notifications
pub async fn create_notification(
    State(state): State<Arc<AppState>>,
    Json(mut req): Json<CreateNotificationConfig>,
) -> ApiResult<Json<serde_json::Value>> {
    // Validate channel type
    match req.channel_type.as_str() {
        "email" | "webhook" | "telegram" => {}
        other => {
            return Err(ApiError::BadRequest(format!("unknown channel_type: {other}")));
        }
    }
    if !req.config_json.is_object() {
        return Err(ApiError::BadRequest("config_json must be a JSON object".to_owned()));
    }
    // Encrypt credentials before they touch the database. A missing/short
    // MASTER_KEY surfaces as a logged 500 rather than a plaintext write.
    req.config_json =
        prepare_config_for_storage(&req.channel_type, &req.config_json, None).map_err(ApiError::Internal)?;

    let row = state.db.create_notification_config(req).await?;
    Ok(Json(
        serde_json::json!({ "success": true, "data": NotificationConfigView::from(&row) }),
    ))
}

/// PUT /api/notifications/:id
///
/// Partial update. Secret members that are omitted or sent as an empty string
/// keep their stored value, so an admin can edit a channel without ever seeing
/// — or having to re-enter — the password, webhook secret, or bot token.
pub async fn update_notification(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateNotificationConfig>,
) -> ApiResult<Json<serde_json::Value>> {
    let existing = state
        .db
        .get_notification_config(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification config {id} not found")))?;

    // The stored secrets are shaped by the channel schema, so the channel type
    // is immutable; echoing back the current value is accepted.
    if let Some(ct) = req.channel_type.as_deref()
        && ct != existing.channel_type
    {
        return Err(ApiError::BadRequest(
            "channel_type cannot be changed; delete and recreate the config".to_owned(),
        ));
    }

    let merged = match req.config_json.as_ref() {
        Some(incoming) => {
            if !incoming.is_object() {
                return Err(ApiError::BadRequest("config_json must be a JSON object".to_owned()));
            }
            Some(
                prepare_config_for_storage(&existing.channel_type, incoming, Some(&existing.config_json))
                    .map_err(ApiError::Internal)?,
            )
        }
        // No channel config supplied: still take the opportunity to re-persist
        // any legacy plaintext secret in encrypted form. Best-effort — if
        // MASTER_KEY is not configured, leave the row as-is instead of failing
        // an update that touched unrelated fields.
        None => match prepare_config_for_storage(&existing.channel_type, &existing.config_json, None) {
            Ok(upgraded) if upgraded == existing.config_json => None,
            Ok(upgraded) => Some(upgraded),
            Err(e) => {
                tracing::warn!("notification {id}: cannot encrypt stored secrets at rest: {e}");
                None
            }
        },
    };

    let row = state
        .db
        .update_notification_config(id, &req, merged.as_ref())
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification config {id} not found")))?;

    Ok(Json(
        serde_json::json!({ "success": true, "data": NotificationConfigView::from(&row) }),
    ))
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

    // Decrypt secrets in-process only; nothing here is echoed to the client.
    let plain_cfg = decrypt_config_for_use(&cfg.channel_type, &cfg.config_json).map_err(ApiError::Internal)?;
    let chan = build_channel(&cfg.channel_type, &plain_cfg)
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Tests may panic on purpose: JSON indexing keeps the assertions readable.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::{
        MAX_RATE_LIMIT_ENTRIES, NotifRateLimitKey, NotificationConfigView, SECRET_MASK, decrypt_config_with_key,
        is_rate_limited, mark_sent, new_rate_limiter, prepare_config_with_key, redact_config, transport_failure,
    };
    use crate::notifications::LazyMasterKey;
    use chrono::Utc;
    use serde_json::{Value, json};
    use uuid::Uuid;
    use waf_common::crypto::derive_key;
    use waf_storage::models::NotificationConfig;

    fn test_key() -> [u8; 32] {
        derive_key("unit-test-master-password-at-least-32-chars")
    }

    fn holder() -> LazyMasterKey {
        LazyMasterKey::with_key(test_key())
    }

    fn row(channel_type: &str, config_json: Value) -> NotificationConfig {
        NotificationConfig {
            id: Uuid::new_v4(),
            name: "alerts".to_owned(),
            host_code: Some("h1".to_owned()),
            event_type: "attack_detected".to_owned(),
            channel_type: channel_type.to_owned(),
            config_json,
            enabled: true,
            rate_limit_secs: 300,
            last_triggered: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ── ① Secrets never reach the wire ────────────────────────────────────────

    #[test]
    fn view_of_email_config_omits_password() {
        let cfg = row(
            "email",
            json!({
                "smtp_host": "smtp.example.com",
                "smtp_port": 587,
                "username": "alerts@example.com",
                "password": "sup3r-s3cret-smtp",
                "from": "waf@example.com",
                "to": ["admin@example.com"],
            }),
        );

        let body = serde_json::to_string(&NotificationConfigView::from(&cfg)).unwrap();
        assert!(!body.contains("sup3r-s3cret-smtp"), "password leaked in view: {body}");
        assert!(body.contains("\"password_set\":true"));
        // Non-secret settings survive so the UI can still render the channel.
        assert!(body.contains("smtp.example.com"));
    }

    #[test]
    fn view_of_webhook_config_omits_secret_and_header_values() {
        let cfg = row(
            "webhook",
            json!({
                "url": "https://hooks.example.com/abc",
                "secret": "hmac-shared-secret",
                "headers": { "Authorization": "Bearer super-token" },
            }),
        );

        let body = serde_json::to_string(&NotificationConfigView::from(&cfg)).unwrap();
        assert!(!body.contains("hmac-shared-secret"), "webhook secret leaked: {body}");
        assert!(!body.contains("super-token"), "webhook header value leaked: {body}");
        assert!(body.contains("\"secret_set\":true"));
        assert!(body.contains("\"headers_set\":true"));
        // Header names are kept (not credentials) but masked in value position.
        assert!(body.contains(SECRET_MASK));
        assert!(body.contains("Authorization"));
    }

    #[test]
    fn view_of_telegram_config_omits_bot_token() {
        let cfg = row(
            "telegram",
            json!({ "bot_token": "12345:AAquickbrownfox", "chat_id": "-100777" }),
        );

        let body = serde_json::to_string(&NotificationConfigView::from(&cfg)).unwrap();
        assert!(!body.contains("AAquickbrownfox"), "bot token leaked: {body}");
        assert!(body.contains("\"bot_token_set\":true"));
    }

    #[test]
    fn missing_secret_reports_not_set() {
        let redacted = redact_config("telegram", &json!({ "chat_id": "-100777" }));
        assert_eq!(redacted["bot_token_set"], json!(false));
    }

    #[test]
    fn ciphertext_is_never_exposed_by_the_view() {
        let stored = prepare_config_with_key(
            "telegram",
            &json!({ "bot_token": "12345:AAquickbrownfox", "chat_id": "-100777" }),
            None,
            &mut holder(),
        )
        .unwrap();

        let body = serde_json::to_string(&NotificationConfigView::from(&row("telegram", stored))).unwrap();
        assert!(!body.contains("$enc"), "ciphertext wrapper leaked: {body}");
    }

    #[test]
    fn raw_model_never_serializes_config_json() {
        let cfg = row("email", json!({ "password": "sup3r-s3cret-smtp" }));
        let raw = serde_json::to_value(&cfg).unwrap();
        assert!(
            raw.get("config_json").is_none(),
            "NotificationConfig must not serialize config_json: {raw}"
        );
    }

    // ── ② Encryption at rest + legacy plaintext compatibility ─────────────────

    #[test]
    fn secrets_are_encrypted_at_rest_and_round_trip() {
        let stored = prepare_config_with_key(
            "email",
            &json!({ "password": "sup3r-s3cret-smtp", "from": "waf@example.com" }),
            None,
            &mut holder(),
        )
        .unwrap();

        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(
            !serialized.contains("sup3r-s3cret-smtp"),
            "plaintext persisted: {serialized}"
        );
        assert!(stored["password"].get("$enc").is_some(), "expected wrapper: {stored}");
        // Non-secret members are stored verbatim.
        assert_eq!(stored["from"], json!("waf@example.com"));

        let plain = decrypt_config_with_key("email", &stored, &mut holder()).unwrap();
        assert_eq!(plain["password"], json!("sup3r-s3cret-smtp"));
        assert_eq!(plain["from"], json!("waf@example.com"));
    }

    #[test]
    fn webhook_headers_are_encrypted_individually() {
        let stored = prepare_config_with_key(
            "webhook",
            &json!({
                "url": "https://hooks.example.com/abc",
                "secret": "hmac-shared-secret",
                "headers": { "Authorization": "Bearer super-token" },
            }),
            None,
            &mut holder(),
        )
        .unwrap();

        let serialized = serde_json::to_string(&stored).unwrap();
        assert!(
            !serialized.contains("super-token"),
            "header plaintext persisted: {serialized}"
        );
        assert!(!serialized.contains("hmac-shared-secret"));

        let plain = decrypt_config_with_key("webhook", &stored, &mut holder()).unwrap();
        assert_eq!(plain["headers"]["Authorization"], json!("Bearer super-token"));
        assert_eq!(plain["secret"], json!("hmac-shared-secret"));
        assert_eq!(plain["url"], json!("https://hooks.example.com/abc"));
    }

    #[test]
    fn legacy_plaintext_rows_are_still_readable() {
        // Rows written before encryption at rest hold bare strings and no
        // MASTER_KEY is available for them — reading must not fail.
        let legacy = json!({
            "smtp_host": "smtp.example.com",
            "password": "legacy-plaintext-password",
            "from": "waf@example.com",
        });

        let plain = decrypt_config_with_key("email", &legacy, &mut LazyMasterKey::new()).unwrap();
        assert_eq!(plain["password"], json!("legacy-plaintext-password"));
        assert_eq!(plain["smtp_host"], json!("smtp.example.com"));
    }

    #[test]
    fn legacy_plaintext_headers_are_still_readable() {
        let legacy = json!({
            "url": "https://hooks.example.com/abc",
            "secret": "legacy-secret",
            "headers": { "Authorization": "legacy-token" },
        });

        let plain = decrypt_config_with_key("webhook", &legacy, &mut LazyMasterKey::new()).unwrap();
        assert_eq!(plain["secret"], json!("legacy-secret"));
        assert_eq!(plain["headers"]["Authorization"], json!("legacy-token"));
    }

    #[test]
    fn legacy_plaintext_is_upgraded_on_next_save() {
        let legacy = json!({ "password": "legacy-plaintext-password", "from": "waf@example.com" });

        // The admin edits the channel without re-typing the password.
        let stored = prepare_config_with_key(
            "email",
            &json!({ "from": "new@example.com" }),
            Some(&legacy),
            &mut holder(),
        )
        .unwrap();

        assert!(stored["password"].get("$enc").is_some(), "not upgraded: {stored}");
        let plain = decrypt_config_with_key("email", &stored, &mut holder()).unwrap();
        assert_eq!(plain["password"], json!("legacy-plaintext-password"));
        assert_eq!(plain["from"], json!("new@example.com"));
    }

    #[test]
    fn re_persisting_a_row_unchanged_only_encrypts_the_plaintext() {
        // Shape used by the PUT path when the caller sends no config_json: the
        // stored row is fed back through the writer, which must encrypt legacy
        // plaintext and leave everything else byte-identical.
        let legacy = json!({
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "password": "legacy-plaintext-password",
            "to": ["admin@example.com"],
        });

        let upgraded = prepare_config_with_key("email", &legacy, None, &mut holder()).unwrap();
        assert!(upgraded["password"].get("$enc").is_some());
        assert_eq!(upgraded["smtp_host"], json!("smtp.example.com"));
        assert_eq!(upgraded["smtp_port"], json!(587));
        assert_eq!(upgraded["to"], json!(["admin@example.com"]));

        // Already-encrypted rows must be a no-op, so the PUT path does not
        // rewrite (and re-salt) config_json on every unrelated field update.
        let again = prepare_config_with_key("email", &upgraded, None, &mut holder()).unwrap();
        assert_eq!(again, upgraded);
    }

    #[test]
    fn redaction_covers_legacy_plaintext_rows() {
        let legacy = json!({ "password": "legacy-plaintext-password", "from": "waf@example.com" });
        let body = serde_json::to_string(&NotificationConfigView::from(&row("email", legacy))).unwrap();
        assert!(
            !body.contains("legacy-plaintext-password"),
            "legacy secret leaked: {body}"
        );
        assert!(body.contains("\"password_set\":true"));
    }

    // ── ③ Update semantics: a blank secret keeps the stored value ─────────────

    #[test]
    fn blank_secret_keeps_the_stored_value() {
        let stored = prepare_config_with_key(
            "email",
            &json!({ "password": "sup3r-s3cret-smtp", "from": "waf@example.com" }),
            None,
            &mut holder(),
        )
        .unwrap();

        // PUT with an empty password (the UI never received the real one).
        let updated = prepare_config_with_key(
            "email",
            &json!({ "password": "", "from": "changed@example.com" }),
            Some(&stored),
            &mut holder(),
        )
        .unwrap();

        assert_eq!(updated["password"], stored["password"], "secret must be preserved");
        assert_eq!(updated["from"], json!("changed@example.com"));
        let plain = decrypt_config_with_key("email", &updated, &mut holder()).unwrap();
        assert_eq!(plain["password"], json!("sup3r-s3cret-smtp"));
    }

    #[test]
    fn omitted_secret_keeps_the_stored_value() {
        let stored = prepare_config_with_key(
            "email",
            &json!({ "password": "sup3r-s3cret-smtp" }),
            None,
            &mut holder(),
        )
        .unwrap();

        let updated = prepare_config_with_key(
            "email",
            &json!({ "from": "x@example.com" }),
            Some(&stored),
            &mut holder(),
        )
        .unwrap();

        assert_eq!(updated["password"], stored["password"]);
    }

    #[test]
    fn redacted_marker_echoed_back_does_not_become_the_secret() {
        // The UI receives `password_set` and no `password`; if a client echoes
        // the whole redacted object back, the flag must not be persisted as a
        // credential and the stored secret must survive.
        let stored = prepare_config_with_key(
            "email",
            &json!({ "password": "sup3r-s3cret-smtp" }),
            None,
            &mut holder(),
        )
        .unwrap();
        let redacted = redact_config("email", &stored);

        let updated = prepare_config_with_key("email", &redacted, Some(&stored), &mut holder()).unwrap();

        assert_eq!(updated["password"], stored["password"]);
        let plain = decrypt_config_with_key("email", &updated, &mut holder()).unwrap();
        assert_eq!(plain["password"], json!("sup3r-s3cret-smtp"));
    }

    #[test]
    fn new_secret_replaces_the_stored_one() {
        let stored =
            prepare_config_with_key("email", &json!({ "password": "old-password" }), None, &mut holder()).unwrap();

        let updated = prepare_config_with_key(
            "email",
            &json!({ "password": "new-password" }),
            Some(&stored),
            &mut holder(),
        )
        .unwrap();

        assert_ne!(updated["password"], stored["password"]);
        let plain = decrypt_config_with_key("email", &updated, &mut holder()).unwrap();
        assert_eq!(plain["password"], json!("new-password"));
    }

    #[test]
    fn blank_header_value_keeps_that_header_only() {
        let stored = prepare_config_with_key(
            "webhook",
            &json!({
                "url": "https://hooks.example.com/abc",
                "headers": { "Authorization": "Bearer keep-me", "X-Env": "prod" },
            }),
            None,
            &mut holder(),
        )
        .unwrap();

        let updated = prepare_config_with_key(
            "webhook",
            &json!({
                "url": "https://hooks.example.com/abc",
                "headers": { "Authorization": "", "X-Env": "staging" },
            }),
            Some(&stored),
            &mut holder(),
        )
        .unwrap();

        let plain = decrypt_config_with_key("webhook", &updated, &mut holder()).unwrap();
        assert_eq!(plain["headers"]["Authorization"], json!("Bearer keep-me"));
        assert_eq!(plain["headers"]["X-Env"], json!("staging"));
    }

    #[test]
    fn creating_without_a_secret_needs_no_master_key() {
        // No secret member supplied → the master key is never touched, so a
        // deployment without MASTER_KEY can still create a plain webhook.
        let stored = prepare_config_with_key(
            "webhook",
            &json!({ "url": "https://hooks.example.com/abc" }),
            None,
            &mut LazyMasterKey::new(),
        )
        .unwrap();
        assert_eq!(stored["url"], json!("https://hooks.example.com/abc"));
        assert!(stored.get("secret").is_none());
    }

    // ── ④ Channel send errors must not echo credential-bearing URLs ──────────

    #[tokio::test]
    async fn transport_errors_never_echo_the_request_url() {
        // reqwest is built with `rustls-no-provider`; the binary installs the
        // provider at startup, so the test has to do the same.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Port 1 on loopback refuses immediately — no external network needed.
        // The URL mimics the Telegram endpoint, whose path carries the token.
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/bot12345:SECRET-BOT-TOKEN/sendMessage")
            .send()
            .await
            .expect_err("connection to port 1 must fail");

        let message = format!("telegram request failed: {}", transport_failure(&err));
        assert!(
            !message.contains("SECRET-BOT-TOKEN"),
            "token leaked into log text: {message}"
        );
        assert!(
            !message.contains("127.0.0.1"),
            "endpoint leaked into log text: {message}"
        );
    }

    // ── ⑤ Per-channel rate limiting ──────────────────────────────────────────

    #[test]
    fn rate_limit_honours_the_channels_configured_window() {
        // Regression: the limiter used to hardcode 5 minutes and ignore the
        // `rate_limit_secs` the operator set in the UI.
        let rl = new_rate_limiter();
        let id = Uuid::new_v4();
        let key: NotifRateLimitKey = (id, Some("h1".to_owned()));

        // Backdate the bucket by a minute so both windows can be evaluated
        // without sleeping: 1h has not elapsed, 30s has.
        rl.insert(key.clone(), Utc::now() - chrono::Duration::seconds(60));
        assert!(is_rate_limited(&rl, &key, 3600), "still inside a 1h cooldown");
        assert!(!is_rate_limited(&rl, &key, 30), "a 30s cooldown has already elapsed");

        // The old hardcoded 5-minute window would have suppressed this.
        assert!(
            !is_rate_limited(&rl, &key, 10),
            "a 10s cooldown is not the old 5min default"
        );
    }

    #[test]
    fn a_zero_window_disables_the_cooldown() {
        let rl = new_rate_limiter();
        let key: NotifRateLimitKey = (Uuid::new_v4(), None);
        mark_sent(&rl, key.clone());
        assert!(!is_rate_limited(&rl, &key, 0));
    }

    #[test]
    fn one_noisy_host_does_not_mute_the_others() {
        // Regression: the limiter used to key on config_id alone, so an attack
        // on one host silenced every other host sharing that channel.
        let rl = new_rate_limiter();
        let id = Uuid::new_v4();
        let noisy: NotifRateLimitKey = (id, Some("under-attack".to_owned()));
        let quiet: NotifRateLimitKey = (id, Some("other-site".to_owned()));

        mark_sent(&rl, noisy.clone());
        assert!(is_rate_limited(&rl, &noisy, 3600));
        assert!(
            !is_rate_limited(&rl, &quiet, 3600),
            "a different host on the same channel must still alert"
        );
    }

    #[test]
    fn an_unseen_bucket_is_never_rate_limited() {
        let rl = new_rate_limiter();
        let key: NotifRateLimitKey = (Uuid::new_v4(), Some("h1".to_owned()));
        assert!(!is_rate_limited(&rl, &key, 3600), "the first event always goes out");
    }

    #[test]
    fn bucket_map_is_swept_when_it_exceeds_the_cap() {
        let rl = new_rate_limiter();
        for i in 0..=MAX_RATE_LIMIT_ENTRIES {
            rl.insert(
                (Uuid::new_v4(), Some(format!("h{i}"))),
                Utc::now() - chrono::Duration::days(2),
            );
        }
        // The insert that crosses the cap triggers the sweep; only the fresh
        // entry survives, so the map cannot grow without bound.
        let fresh: NotifRateLimitKey = (Uuid::new_v4(), Some("fresh".to_owned()));
        mark_sent(&rl, fresh.clone());
        assert!(
            rl.len() <= MAX_RATE_LIMIT_ENTRIES,
            "stale buckets are swept: {}",
            rl.len()
        );
        assert!(rl.contains_key(&fresh), "the entry just written survives the sweep");
    }

    #[test]
    fn unknown_channel_type_has_no_secret_members() {
        // Defensive: an unrecognised channel is passed through untouched rather
        // than silently dropping data.
        let stored = prepare_config_with_key(
            "carrier-pigeon",
            &json!({ "coop": "north" }),
            None,
            &mut LazyMasterKey::new(),
        )
        .unwrap();
        assert_eq!(stored["coop"], json!("north"));
    }
}
