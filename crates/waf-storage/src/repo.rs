use chrono::{DateTime, Utc};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::error::StorageError;
use crate::models::{
    AdminUser, AllowIp, AllowUrl, AttackLog, AttackLogQuery, AuditLogEntry, AuditLogQuery, BlockIp, BlockUrl,
    BotPattern, Certificate, CreateAdminUser, CreateBotPattern, CreateCertificate, CreateCrowdSecEvent,
    CreateCustomRule, CreateHost, CreateIpRule, CreateLbBackend, CreateNotificationConfig, CreateRuleOverride,
    CreateSecurityEvent, CreateSemanticObservation, CreateSensitivePattern, CreateTunnel, CreateUrlRule,
    CreateWasmPlugin, CrowdSecConfigRow, CrowdSecDecisionRow, CrowdSecEventQuery, CrowdSecEventRow, CustomRule,
    GeoDistEntry, GeoStats, Host, HotlinkConfig, LabeledCount, LbBackend, NotificationConfig, NotificationLog,
    RefreshToken, RuleOverride, SecurityEvent, SecurityEventQuery, SemanticObservation, SemanticObservationFilter,
    SemanticObservationQuery, SensitivePattern, StatsOverview, TimeSeriesPoint, TopEntry, TunnelRow, UpdateBotPattern,
    UpdateCertificatePem, UpdateHost, UpdateNotificationConfig, UpdateRuleOverride, UpsertCrowdSecConfig,
    UpsertHotlinkConfig, WasmPluginRow,
};
use crate::retention::{DEFAULT_DELETE_BATCH_SIZE, RetentionTable, prune_in_batches};
use waf_common::notify::{NotificationEvent, NotificationEventKind};

/// The `action` value that means "this request was actually stopped".
///
/// Only a real block raises an `attack_detected` notification. `log_only`
/// (detect-only hosts, the Lane 2 shadow pipeline) and `allow` rows are written
/// to the same tables but describe traffic that was served, so alerting on them
/// would flood an operator with non-events.
const ACTION_BLOCK: &str = "block";

/// Longest request path echoed into a notification body.
///
/// The path is attacker-controlled and can be megabytes long; the alert only
/// needs enough of it to be recognisable. Full detail stays in `security_events`
/// / `attack_logs`, which the alert points at.
const NOTIFY_PATH_CHARS: usize = 120;

/// Truncate an attacker-controlled string to a bounded prefix.
fn clip(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(max_chars).collect();
    out.push('…');
    out
}

/// Render the shared body of an `attack_detected` alert.
///
/// `NotificationEvent::new` sanitises and length-caps the result, so hostile
/// bytes in `path` or `rule_name` cannot break out of the message or inject an
/// email header.
fn attack_message(host_code: &str, client_ip: &str, method: &str, path: &str, rule_name: &str) -> String {
    format!(
        "The WAF blocked a request.\n\nHost:   {host_code}\nClient: {client_ip}\nRule:   {rule_name}\nRequest: {method} {}",
        clip(path, NOTIFY_PATH_CHARS)
    )
}

/// Build the `attack_detected` event for a blocked request.
///
/// The coalescing key is the **host**, deliberately not the rule: a single
/// scanner trips dozens of distinct rules in a second, and an operator wants one
/// "host X is under attack" alert, not one per signature.
fn attack_event(host_code: &str, client_ip: &str, method: &str, path: &str, rule_name: &str) -> NotificationEvent {
    NotificationEvent::new(
        NotificationEventKind::AttackDetected,
        Some(host_code.to_owned()),
        host_code,
        &format!("[PRX-WAF] Attack blocked on {host_code}"),
        &attack_message(host_code, client_ip, method, path, rule_name),
    )
}

/// Column projection for every `hosts` read.
///
/// `remote_ip` is a Postgres `INET` column, but the `Host` model decodes it as
/// `Option<String>` and sqlx is built without the `ipnetwork` feature, so it has
/// no native `INET` codec. Selecting the raw column would fail to decode; the
/// `host(remote_ip)` render yields a plain address with no `/32`|`/128` netmask,
/// giving a byte-for-byte create → select round-trip. Kept in one constant so
/// the projection can never drift between the list/get/insert/update paths.
const HOST_COLUMNS: &str = "id, code, host, port, ssl, guard_status, remote_host, remote_port, \
     host(remote_ip) AS remote_ip, cert_file, key_file, remarks, start_status, exclude_url_log, \
     is_enable_load_balance, load_balance_stage, defense_json, log_only_mode, created_at, updated_at";

/// Column projection for every `attack_logs` read.
///
/// Same reason as [`HOST_COLUMNS`]: `client_ip` is `INET` while [`AttackLog`]
/// decodes it as `String`, and sqlx has no `INET` codec here, so a bare
/// `SELECT *` fails to decode. `host(client_ip)` renders the bare address with
/// no `/32`|`/128` suffix, so an insert round-trips byte-for-byte.
const ATTACK_LOG_COLUMNS: &str = "id, host_code, host, host(client_ip) AS client_ip, method, path, query, \
     rule_id, rule_name, action, phase, detail, request_headers, geo_info, created_at";

/// Reject a value that is not a bare IP address so it surfaces as a clean
/// [`StorageError::InvalidInput`] instead of a raw Postgres `22P02` bubbling up
/// out of an `::inet` cast.
fn validate_ip(field: &str, value: &str) -> Result<(), StorageError> {
    if value.parse::<std::net::IpAddr>().is_err() {
        return Err(StorageError::InvalidInput(format!(
            "{field} must be a valid IP address, got: {value}"
        )));
    }
    Ok(())
}

/// Reject a non-IP `remote_ip` before the `::inet` cast. `None` (→ SQL `NULL`)
/// is always allowed.
fn validate_remote_ip(remote_ip: Option<&str>) -> Result<(), StorageError> {
    remote_ip.map_or_else(|| Ok(()), |ip| validate_ip("remote_ip", ip))
}

/// Reject an `addr/prefix` that Postgres would refuse, so a bad CIDR in a
/// user-supplied filter becomes a 400 rather than a raw `22P02` 500.
fn validate_cidr(value: &str) -> Result<(), StorageError> {
    let invalid = || StorageError::InvalidInput(format!("client_ip must be an IP or CIDR, got: {value}"));
    let Some((addr, prefix)) = value.split_once('/') else {
        return Err(invalid());
    };
    let addr: std::net::IpAddr = addr.parse().map_err(|_| invalid())?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let bits: u32 = prefix.parse().map_err(|_| invalid())?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return Err(invalid());
    }
    Ok(())
}

/// Blank filter values (the admin UI binds its inputs to `""`) mean "no
/// filter", not "match the empty string".
fn filter_value(raw: Option<&String>) -> Option<&str> {
    raw.map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// SQL comparison for the optional `client_ip` filter on `attack_logs`.
///
/// The column is `INET`, so a bare text parameter has no matching operator at
/// all (`42883: operator does not exist: inet = text`) — the predicate has to
/// name the cast. Two shapes are accepted and they deliberately do *not* share
/// one operator:
///
/// * a plain address uses `=`, which `idx_attack_logs_client_ip` (btree) can
///   serve — this is the overwhelmingly common lookup;
/// * a CIDR uses `<<=` (contained-within-or-equal), which is the reason the
///   column is `INET` in the first place: "everything from 10.0.0.0/8" is what
///   an operator asks during an incident. btree cannot index `<<=`, so it is
///   only reached when the caller actually passed a network.
///
/// The value itself always stays a bound parameter; only the operator is chosen
/// in Rust, from a closed set of two literals.
fn client_ip_predicate(filter: Option<&str>) -> Result<&'static str, StorageError> {
    const EXACT: &str = "client_ip = $2::inet";
    match filter {
        // No filter: `$2` is SQL NULL and the `IS NULL` arm short-circuits, so
        // either operator is inert. Keep the indexable one.
        None => Ok(EXACT),
        Some(value) if value.contains('/') => {
            validate_cidr(value)?;
            Ok("client_ip <<= $2::inet")
        }
        Some(value) => {
            validate_ip("client_ip", value)?;
            Ok(EXACT)
        }
    }
}

/// Serialise an optional [`DefenseConfig`](waf_common::DefenseConfig) for the
/// `defense_json` JSONB column. `None` → SQL `NULL` (runtime falls back to the
/// default all-on config). Serialisation of a fixed-shape struct of scalars
/// cannot realistically fail, but the error is surfaced as `InvalidInput`
/// rather than panicking (iron rule: no unwrap in production).
fn defense_json(defense_config: Option<&waf_common::DefenseConfig>) -> Result<Option<serde_json::Value>, StorageError> {
    match defense_config {
        Some(cfg) => Ok(Some(serde_json::to_value(cfg).map_err(|e| {
            StorageError::InvalidInput(format!("defense_config serialisation failed: {e}"))
        })?)),
        None => Ok(None),
    }
}

impl Database {
    // ─── Hosts ───────────────────────────────────────────────────────────────

    pub async fn list_hosts(&self) -> Result<Vec<Host>, StorageError> {
        let sql = format!("SELECT {HOST_COLUMNS} FROM hosts ORDER BY created_at DESC");
        let rows = sqlx::query_as::<_, Host>(&sql).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    pub async fn get_host(&self, id: Uuid) -> Result<Option<Host>, StorageError> {
        let sql = format!("SELECT {HOST_COLUMNS} FROM hosts WHERE id = $1");
        let row = sqlx::query_as::<_, Host>(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn get_host_by_code(&self, code: &str) -> Result<Option<Host>, StorageError> {
        let sql = format!("SELECT {HOST_COLUMNS} FROM hosts WHERE code = $1");
        let row = sqlx::query_as::<_, Host>(&sql)
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row)
    }

    pub async fn create_host(&self, req: CreateHost) -> Result<Host, StorageError> {
        validate_remote_ip(req.remote_ip.as_deref())?;
        let defense = defense_json(req.defense_config.as_ref())?;

        let id = Uuid::new_v4();
        let code = Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        let now = chrono::Utc::now();

        let sql = format!(
            "INSERT INTO hosts (
                id, code, host, port, ssl, guard_status,
                remote_host, remote_port, remote_ip, cert_file, key_file,
                remarks, start_status, log_only_mode, defense_json,
                is_enable_load_balance, load_balance_stage,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9::inet, $10, $11,
                $12, $13, $14, $15::jsonb,
                false, 0,
                $16, $16
            ) RETURNING {HOST_COLUMNS}"
        );
        let row = sqlx::query_as::<_, Host>(&sql)
            .bind(id)
            .bind(&code)
            .bind(&req.host)
            .bind(req.port)
            .bind(req.ssl)
            .bind(req.guard_status)
            .bind(&req.remote_host)
            .bind(req.remote_port)
            .bind(&req.remote_ip)
            .bind(&req.cert_file)
            .bind(&req.key_file)
            .bind(&req.remarks)
            .bind(req.start_status)
            .bind(req.log_only_mode)
            .bind(defense)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;

        debug!("Created host: {} (code={})", req.host, code);
        Ok(row)
    }

    pub async fn update_host(&self, id: Uuid, req: UpdateHost) -> Result<Option<Host>, StorageError> {
        validate_remote_ip(req.remote_ip.as_deref())?;
        let defense = defense_json(req.defense_config.as_ref())?;

        let now = chrono::Utc::now();

        let sql = format!(
            "UPDATE hosts SET
                host = COALESCE($2, host),
                port = COALESCE($3, port),
                ssl = COALESCE($4, ssl),
                guard_status = COALESCE($5, guard_status),
                remote_host = COALESCE($6, remote_host),
                remote_port = COALESCE($7, remote_port),
                remote_ip = COALESCE($8::inet, remote_ip),
                cert_file = COALESCE($9, cert_file),
                key_file = COALESCE($10, key_file),
                remarks = COALESCE($11, remarks),
                start_status = COALESCE($12, start_status),
                log_only_mode = COALESCE($13, log_only_mode),
                defense_json = COALESCE($14::jsonb, defense_json),
                updated_at = $15
            WHERE id = $1
            RETURNING {HOST_COLUMNS}"
        );
        let row = sqlx::query_as::<_, Host>(&sql)
            .bind(id)
            .bind(req.host)
            .bind(req.port)
            .bind(req.ssl)
            .bind(req.guard_status)
            .bind(req.remote_host)
            .bind(req.remote_port)
            .bind(req.remote_ip)
            .bind(req.cert_file)
            .bind(req.key_file)
            .bind(req.remarks)
            .bind(req.start_status)
            .bind(req.log_only_mode)
            .bind(defense)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row)
    }

    pub async fn delete_host(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM hosts WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Allow IPs ───────────────────────────────────────────────────────────

    pub async fn list_allow_ips(&self, host_code: Option<&str>) -> Result<Vec<AllowIp>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, AllowIp>("SELECT * FROM allow_ips WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, AllowIp>("SELECT * FROM allow_ips ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_allow_ip(&self, req: CreateIpRule) -> Result<AllowIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowIp>(
            r"INSERT INTO allow_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.ip_cidr)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_allow_ip(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM allow_ips WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Block IPs ───────────────────────────────────────────────────────────

    pub async fn list_block_ips(&self, host_code: Option<&str>) -> Result<Vec<BlockIp>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, BlockIp>("SELECT * FROM block_ips WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, BlockIp>("SELECT * FROM block_ips ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_block_ip(&self, req: CreateIpRule) -> Result<BlockIp, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockIp>(
            r"INSERT INTO block_ips (id, host_code, ip_cidr, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $5)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.ip_cidr)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_block_ip(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM block_ips WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Allow URLs ──────────────────────────────────────────────────────────

    pub async fn list_allow_urls(&self, host_code: Option<&str>) -> Result<Vec<AllowUrl>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, AllowUrl>("SELECT * FROM allow_urls WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, AllowUrl>("SELECT * FROM allow_urls ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_allow_url(&self, req: CreateUrlRule) -> Result<AllowUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, AllowUrl>(
            r"INSERT INTO allow_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.url_pattern)
        .bind(&req.match_type)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_allow_url(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM allow_urls WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Block URLs ──────────────────────────────────────────────────────────

    pub async fn list_block_urls(&self, host_code: Option<&str>) -> Result<Vec<BlockUrl>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, BlockUrl>("SELECT * FROM block_urls WHERE host_code = $1 ORDER BY created_at DESC")
                    .bind(code)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query_as::<_, BlockUrl>("SELECT * FROM block_urls ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_block_url(&self, req: CreateUrlRule) -> Result<BlockUrl, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, BlockUrl>(
            r"INSERT INTO block_urls (id, host_code, url_pattern, match_type, remarks, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $6)
               RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.url_pattern)
        .bind(&req.match_type)
        .bind(&req.remarks)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_block_url(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM block_urls WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ─── Attack Logs ─────────────────────────────────────────────────────────

    pub async fn create_attack_log(&self, log: AttackLog) -> Result<(), StorageError> {
        // `client_ip` is `INET NOT NULL`; without the explicit cast Postgres
        // rejects the text parameter outright (`42804`). The only caller runs
        // detached and downgrades the failure to a `warn!`, so a silent break
        // here means the table simply never fills — validate first so a bad
        // address is a named error instead of a raw `22P02`.
        validate_ip("client_ip", &log.client_ip)?;
        sqlx::query(
            r"INSERT INTO attack_logs (
                id, host_code, host, client_ip, method, path, query,
                rule_id, rule_name, action, phase, detail,
                request_headers, geo_info, created_at
            ) VALUES ($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(log.id)
        .bind(&log.host_code)
        .bind(&log.host)
        .bind(&log.client_ip)
        .bind(&log.method)
        .bind(&log.path)
        .bind(&log.query)
        .bind(&log.rule_id)
        .bind(&log.rule_name)
        .bind(&log.action)
        .bind(&log.phase)
        .bind(&log.detail)
        .bind(&log.request_headers)
        .bind(&log.geo_info)
        .bind(log.created_at)
        .execute(&self.pool)
        .await?;

        // IP/URL blacklist blocks land here rather than in `security_events`
        // (see `waf_engine::engine::log_attack`), so the notification hook has
        // to cover both writers to catch every enforced block.
        if log.action == ACTION_BLOCK {
            self.publish_notification(attack_event(
                &log.host_code,
                &log.client_ip,
                &log.method,
                &log.path,
                &log.rule_name,
            ));
        }
        Ok(())
    }

    pub async fn list_attack_logs(&self, query: &AttackLogQuery) -> Result<(Vec<AttackLog>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * page_size;

        let client_ip = filter_value(query.client_ip.as_ref());
        // Only the operator varies, and only across two hard-coded literals;
        // every value below is still a bound parameter.
        let ip_pred = client_ip_predicate(client_ip)?;
        let filters = format!(
            "WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR {ip_pred})
                 AND ($3::text IS NULL OR action = $3)
                 AND ($4::text IS NULL OR geo_info->>'iso_code' = $4)
                 AND ($5::text IS NULL OR geo_info->>'country' ILIKE '%' || $5 || '%')"
        );

        // Count query
        let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM attack_logs {filters}"))
            .bind(&query.host_code)
            .bind(client_ip)
            .bind(&query.action)
            .bind(&query.iso_code)
            .bind(&query.country)
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query_as::<_, AttackLog>(&format!(
            "SELECT {ATTACK_LOG_COLUMNS} FROM attack_logs {filters}
               ORDER BY created_at DESC
               LIMIT $6 OFFSET $7"
        ))
        .bind(&query.host_code)
        .bind(client_ip)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ─── Security Events ─────────────────────────────────────────────────────

    pub async fn create_security_event(&self, req: CreateSecurityEvent) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO security_events
               (host_code, client_ip, method, path, rule_id, rule_name, action, detail, geo_info)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&req.host_code)
        .bind(&req.client_ip)
        .bind(&req.method)
        .bind(&req.path)
        .bind(&req.rule_id)
        .bind(&req.rule_name)
        .bind(&req.action)
        .bind(&req.detail)
        .bind(&req.geo_info)
        .execute(&self.pool)
        .await?;

        // Broadcast to WebSocket subscribers
        if let Ok(event_json) = serde_json::to_value(&req) {
            self.broadcast_event(event_json);
        }

        // Raise an operator notification for real blocks only. This is the
        // funnel every detector reaches (`waf_engine::engine::log_security_event`
        // and the Lane 2 semantic sink both end up here), and it already runs
        // off the request hot path — the engine writes security events from a
        // detached task, never inline in `request_filter`.
        if req.action == ACTION_BLOCK {
            self.publish_notification(attack_event(
                &req.host_code,
                &req.client_ip,
                &req.method,
                &req.path,
                &req.rule_name,
            ));
        }

        Ok(())
    }

    // ─── Semantic Observations (Lane 2) ──────────────────────────────────────

    /// Insert one Lane 2 semantic observation (plan §13.1). Parameterised
    /// query; the JSONB `observations` array is de-identified by the caller.
    pub async fn insert_semantic_observation(&self, req: CreateSemanticObservation) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO semantic_observations
               (host_code, client_ip, req_id, scope, request_score, recommendation,
                degraded, exhausted, pipeline, schema_version, observations)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&req.host_code)
        .bind(&req.client_ip)
        .bind(&req.req_id)
        .bind(&req.scope)
        .bind(req.request_score)
        .bind(&req.recommendation)
        .bind(req.degraded)
        .bind(req.exhausted)
        .bind(&req.pipeline)
        .bind(req.schema_version)
        .bind(&req.observations)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List semantic observations, most recent first, optionally filtered by
    /// host and paginated.
    pub async fn list_semantic_observations(
        &self,
        query: SemanticObservationQuery,
    ) -> Result<Vec<SemanticObservation>, StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(50).clamp(1, 500);
        let offset = (page - 1) * page_size;

        let rows = match query.host_code {
            Some(host) => {
                sqlx::query_as::<_, SemanticObservation>(
                    r"SELECT * FROM semantic_observations
                       WHERE host_code = $1
                       ORDER BY created_at DESC
                       LIMIT $2 OFFSET $3",
                )
                .bind(host)
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, SemanticObservation>(
                    r"SELECT * FROM semantic_observations
                       ORDER BY created_at DESC
                       LIMIT $1 OFFSET $2",
                )
                .bind(page_size)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    /// Query semantic observations for the read-only P1a-2 admin panel with
    /// rich filtering, most recent first. Returns the requested page plus the
    /// total number of matching rows for pagination.
    ///
    /// Every predicate is a bound parameter — no string concatenation. The
    /// `attack` / `rule_key` filters use JSONB containment (`observations @>
    /// $probe`) so they match a signal *inside* the de-identified array; the
    /// probe object is built in Rust and bound as a single `jsonb` parameter.
    pub async fn query_semantic_observations(
        &self,
        filter: &SemanticObservationFilter,
    ) -> Result<(Vec<SemanticObservation>, i64), StorageError> {
        let page = filter.page.unwrap_or(1).max(1);
        let page_size = filter.page_size.unwrap_or(50).clamp(1, 500);
        let offset = (page - 1) * page_size;

        // Containment probes: `[{"attack": <v>}]` / `[{"rule_key": <v>}]`, bound
        // as jsonb. `None` binds SQL NULL, which the `$n::jsonb IS NULL` guard
        // turns into "no filter".
        let attack_probe = filter.attack.as_ref().map(|a| serde_json::json!([{ "attack": a }]));
        let rule_key_probe = filter.rule_key.as_ref().map(|k| serde_json::json!([{ "rule_key": k }]));
        let min_score = filter.min_score.map(i32::from);

        let total: i64 = sqlx::query_scalar(
            r"SELECT COUNT(*) FROM semantic_observations
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::jsonb IS NULL OR observations @> $2)
                 AND ($3::jsonb IS NULL OR observations @> $3)
                 AND ($4::int IS NULL OR request_score >= $4)
                 AND ($5::timestamptz IS NULL OR created_at >= $5)
                 AND ($6::timestamptz IS NULL OR created_at <= $6)",
        )
        .bind(&filter.host_code)
        .bind(attack_probe.clone())
        .bind(rule_key_probe.clone())
        .bind(min_score)
        .bind(filter.from)
        .bind(filter.to)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, SemanticObservation>(
            r"SELECT * FROM semantic_observations
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::jsonb IS NULL OR observations @> $2)
                 AND ($3::jsonb IS NULL OR observations @> $3)
                 AND ($4::int IS NULL OR request_score >= $4)
                 AND ($5::timestamptz IS NULL OR created_at >= $5)
                 AND ($6::timestamptz IS NULL OR created_at <= $6)
               ORDER BY created_at DESC
               LIMIT $7 OFFSET $8",
        )
        .bind(&filter.host_code)
        .bind(attack_probe)
        .bind(rule_key_probe)
        .bind(min_score)
        .bind(filter.from)
        .bind(filter.to)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    /// Attack-family distribution for the observation panel: number of distinct
    /// observations carrying each `attack` family within the last `window_hours`.
    ///
    /// The window cutoff is computed in Rust and bound as `$1` (no `INTERVAL`
    /// string interpolation); `window_hours` / `limit` are clamped to sane
    /// bounds so a caller can never request an unbounded scan.
    pub async fn semantic_observation_family_counts(
        &self,
        window_hours: i64,
        limit: i64,
    ) -> Result<Vec<LabeledCount>, StorageError> {
        let cutoff = Self::window_cutoff(window_hours)?;
        let limit = limit.clamp(1, 100);
        let rows = sqlx::query_as::<_, LabeledCount>(
            r"SELECT COALESCE(sig->>'attack', 'unknown') AS label,
                     COUNT(DISTINCT s.id) AS count
               FROM semantic_observations s,
                    LATERAL jsonb_array_elements(s.observations) AS sig
               WHERE s.created_at >= $1
               GROUP BY label
               ORDER BY count DESC
               LIMIT $2",
        )
        .bind(cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Recommendation distribution (`block` / `log` / `none`) for the observation
    /// panel within the last `window_hours`. Same bounded-window contract as
    /// [`Self::semantic_observation_family_counts`].
    pub async fn semantic_observation_recommendation_counts(
        &self,
        window_hours: i64,
    ) -> Result<Vec<LabeledCount>, StorageError> {
        let cutoff = Self::window_cutoff(window_hours)?;
        let rows = sqlx::query_as::<_, LabeledCount>(
            r"SELECT recommendation AS label, COUNT(*) AS count
               FROM semantic_observations
               WHERE created_at >= $1
               GROUP BY recommendation
               ORDER BY count DESC",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Compute a `now() - window_hours` cutoff, clamping the window to
    /// `1..=2160` hours (90 days) and rejecting an overflowing value instead of
    /// panicking.
    fn window_cutoff(window_hours: i64) -> Result<DateTime<Utc>, StorageError> {
        let window_hours = window_hours.clamp(1, 24 * 90);
        let delta = chrono::TimeDelta::try_hours(window_hours)
            .ok_or_else(|| StorageError::InvalidInput(format!("window_hours {window_hours} is out of range")))?;
        Ok(chrono::Utc::now() - delta)
    }

    /// Delete rows older than `retention_days` from one observability / PII
    /// table, in bounded batches.
    ///
    /// This is the statement behind the retention scheduler
    /// ([`crate::retention`]). Safety properties:
    ///
    /// * **No dynamic SQL.** The table name cannot be a bind parameter, so it
    ///   comes from the closed [`RetentionTable`] enum and the statement text is
    ///   a compile-time literal. No configuration value reaches it.
    /// * **Fully parameterised bounds.** The cutoff is computed in Rust
    ///   (`now() - retention_days`) and bound as `$1`; the batch size is bound as
    ///   `$2`. No `INTERVAL` or `LIMIT` string interpolation.
    /// * **Bounded lock hold.** Each statement deletes at most `batch_size` rows
    ///   (`ctid IN (SELECT … LIMIT $2)`) and commits, so a multi-million-row
    ///   backlog never becomes one long-running transaction. The loop repeats
    ///   until a short batch proves the expired set is drained.
    ///
    /// `retention_days` must be positive: a zero or negative window would delete
    /// every row, so it is rejected as invalid input rather than silently wiping
    /// the table. An out-of-range day count (would overflow the timestamp
    /// arithmetic) is likewise rejected instead of panicking.
    ///
    /// Returns the total number of rows deleted across all batches.
    pub async fn prune_retention_table(
        &self,
        table: RetentionTable,
        retention_days: i64,
        batch_size: i64,
    ) -> Result<u64, StorageError> {
        if retention_days <= 0 {
            return Err(StorageError::InvalidInput(format!(
                "retention_days must be positive, got {retention_days}"
            )));
        }
        let delta = chrono::TimeDelta::try_days(retention_days)
            .ok_or_else(|| StorageError::InvalidInput(format!("retention_days {retention_days} is out of range")))?;
        let cutoff = chrono::Utc::now() - delta;
        let sql = table.delete_batch_sql();
        let pool = &self.pool;

        prune_in_batches(table.name(), batch_size, move |limit| async move {
            let result = sqlx::query(sql).bind(cutoff).bind(limit).execute(pool).await?;
            Ok(result.rows_affected())
        })
        .await
    }

    /// Prune Lane 2 semantic observations older than `retention_days` — the
    /// retention / TTL enforcement for the shadow telemetry table (plan §13.1).
    ///
    /// Thin wrapper over [`Self::prune_retention_table`] with the default batch
    /// size, kept as the named entry point for the Lane 2 table.
    pub async fn prune_semantic_observations(&self, retention_days: i64) -> Result<u64, StorageError> {
        self.prune_retention_table(
            RetentionTable::SemanticObservations,
            retention_days,
            DEFAULT_DELETE_BATCH_SIZE,
        )
        .await
    }

    // ─── Certificates ─────────────────────────────────────────────────────────

    pub async fn list_certificates(&self, host_code: Option<&str>) -> Result<Vec<Certificate>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, Certificate>(
                    "SELECT * FROM certificates WHERE host_code = $1 ORDER BY created_at DESC",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Certificate>("SELECT * FROM certificates ORDER BY created_at DESC")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn get_certificate(&self, id: Uuid) -> Result<Option<Certificate>, StorageError> {
        Ok(
            sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_certificate_by_domain(&self, domain: &str) -> Result<Option<Certificate>, StorageError> {
        Ok(sqlx::query_as::<_, Certificate>(
            "SELECT * FROM certificates WHERE domain = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn create_certificate(&self, req: CreateCertificate) -> Result<Certificate, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, Certificate>(
            r"INSERT INTO certificates (id, host_code, domain, cert_pem, key_pem, chain_pem, auto_renew, status, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$8) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.domain)
        .bind(&req.cert_pem).bind(&req.key_pem).bind(&req.chain_pem)
        .bind(req.auto_renew.unwrap_or(true)).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn update_certificate_status(
        &self,
        id: Uuid,
        status: &str,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE certificates SET status=$2, error_msg=$3, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .bind(error_msg)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_certificate_pem(&self, params: &UpdateCertificatePem<'_>) -> Result<(), StorageError> {
        sqlx::query(
            r"UPDATE certificates SET cert_pem=$2, key_pem=$3, chain_pem=$4,
               not_before=$5, not_after=$6, issuer=$7, subject=$8,
               status='active', error_msg=NULL, updated_at=NOW() WHERE id=$1",
        )
        .bind(params.id)
        .bind(params.cert_pem)
        .bind(params.key_pem)
        .bind(params.chain_pem)
        .bind(params.not_before)
        .bind(params.not_after)
        .bind(params.issuer)
        .bind(params.subject)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_certificates_due_renewal(&self, days_before: i64) -> Result<Vec<Certificate>, StorageError> {
        let threshold = chrono::Utc::now() + chrono::Duration::days(days_before);
        let rows = sqlx::query_as::<_, Certificate>(
            r"SELECT * FROM certificates
               WHERE auto_renew = TRUE AND status = 'active'
                 AND not_after IS NOT NULL AND not_after < $1",
        )
        .bind(threshold)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Active certificates whose `not_after` falls inside the next
    /// `days_ahead` days — including ones that have **already expired**.
    ///
    /// Deliberately not the same query as [`Self::list_certificates_due_renewal`]:
    /// that one is the ACME renewal worklist and filters on `auto_renew = TRUE`,
    /// because there is nothing it can do about a manually-installed cert. An
    /// expiry *alert* is exactly the opposite — a hand-managed certificate about
    /// to lapse is the case an operator most needs to hear about.
    pub async fn list_certificates_expiring_within(&self, days_ahead: i64) -> Result<Vec<Certificate>, StorageError> {
        let threshold = chrono::Utc::now() + chrono::Duration::days(days_ahead.max(0));
        let rows = sqlx::query_as::<_, Certificate>(
            r"SELECT * FROM certificates
               WHERE status = 'active'
                 AND not_after IS NOT NULL AND not_after < $1
               ORDER BY not_after",
        )
        .bind(threshold)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete_certificate(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM certificates WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Custom Rules ─────────────────────────────────────────────────────────

    pub async fn list_custom_rules(&self, host_code: Option<&str>) -> Result<Vec<CustomRule>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, CustomRule>(
                    "SELECT * FROM custom_rules WHERE host_code = $1 ORDER BY priority, created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, CustomRule>("SELECT * FROM custom_rules ORDER BY priority, created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn get_custom_rule(&self, id: Uuid) -> Result<Option<CustomRule>, StorageError> {
        Ok(
            sqlx::query_as::<_, CustomRule>("SELECT * FROM custom_rules WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_custom_rule(&self, req: CreateCustomRule) -> Result<CustomRule, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, CustomRule>(
            r"INSERT INTO custom_rules
               (id, host_code, name, description, priority, enabled, condition_op, conditions,
                action, action_status, action_msg, script, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13) RETURNING *",
        )
        .bind(id)
        .bind(&req.host_code)
        .bind(&req.name)
        .bind(&req.description)
        .bind(req.priority.unwrap_or(100))
        .bind(req.enabled.unwrap_or(true))
        .bind(req.condition_op.as_deref().unwrap_or("and"))
        .bind(&req.conditions)
        .bind(req.action.as_deref().unwrap_or("block"))
        .bind(req.action_status.unwrap_or(403))
        .bind(&req.action_msg)
        .bind(&req.script)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_custom_rule(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM custom_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn set_custom_rule_enabled(&self, id: Uuid, enabled: bool) -> Result<bool, StorageError> {
        let r = sqlx::query("UPDATE custom_rules SET enabled=$2, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Sensitive Patterns ───────────────────────────────────────────────────

    pub async fn list_sensitive_patterns(
        &self,
        host_code: Option<&str>,
    ) -> Result<Vec<SensitivePattern>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, SensitivePattern>(
                    "SELECT * FROM sensitive_patterns WHERE host_code = $1 AND enabled = TRUE ORDER BY created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, SensitivePattern>(
                    "SELECT * FROM sensitive_patterns WHERE enabled = TRUE ORDER BY created_at",
                )
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_sensitive_pattern(
        &self,
        req: CreateSensitivePattern,
    ) -> Result<SensitivePattern, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, SensitivePattern>(
            r"INSERT INTO sensitive_patterns
               (id, host_code, pattern, pattern_type, check_request, check_response, action, remarks, enabled, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,$9,$9) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.pattern)
        .bind(req.pattern_type.as_deref().unwrap_or("word"))
        .bind(req.check_request.unwrap_or(true))
        .bind(req.check_response.unwrap_or(false))
        .bind(req.action.as_deref().unwrap_or("block"))
        .bind(&req.remarks).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn delete_sensitive_pattern(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM sensitive_patterns WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Bot Patterns ─────────────────────────────────────────────────────────

    /// Every operator bot pattern, newest last.
    ///
    /// `enabled_only` is what the engine passes on reload; the admin API passes
    /// `false` so a disabled rule is still listed and can be switched back on.
    pub async fn list_bot_patterns(&self, enabled_only: bool) -> Result<Vec<BotPattern>, StorageError> {
        let rows = if enabled_only {
            sqlx::query_as::<_, BotPattern>("SELECT * FROM bot_patterns WHERE enabled = TRUE ORDER BY id")
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as::<_, BotPattern>("SELECT * FROM bot_patterns ORDER BY id")
                .fetch_all(&self.pool)
                .await?
        };
        Ok(rows)
    }

    /// How many patterns the engine would load right now. Used to enforce the
    /// engine's `MAX_USER_PATTERNS` cap at the API boundary, so an operator is
    /// told the set is full instead of writing a row that would be dropped on
    /// the next reload.
    pub async fn count_enabled_bot_patterns(&self) -> Result<i64, StorageError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bot_patterns WHERE enabled = TRUE")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Insert one pattern. The regex itself is validated by the caller (the API
    /// and the CLI both run `waf_engine::checks::bot::validate_user_pattern`),
    /// which is where the compiler lives.
    pub async fn create_bot_pattern(&self, req: CreateBotPattern) -> Result<BotPattern, StorageError> {
        let row = sqlx::query_as::<_, BotPattern>(
            r"INSERT INTO bot_patterns (name, pattern, pattern_type, action, description, enabled)
               VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
        )
        .bind(&req.name)
        .bind(&req.pattern)
        .bind(req.pattern_type.as_deref().unwrap_or("ua"))
        .bind(req.action.as_deref().unwrap_or("block"))
        .bind(&req.description)
        .bind(req.enabled.unwrap_or(true))
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Patch one pattern. A `None` field keeps its stored value — including
    /// `description`, which therefore cannot be cleared through this call.
    pub async fn update_bot_pattern(&self, id: i32, req: UpdateBotPattern) -> Result<Option<BotPattern>, StorageError> {
        let row = sqlx::query_as::<_, BotPattern>(
            r"UPDATE bot_patterns
                 SET name        = COALESCE($2, name),
                     pattern     = COALESCE($3, pattern),
                     action      = COALESCE($4, action),
                     description = COALESCE($5, description),
                     enabled     = COALESCE($6, enabled),
                     updated_at  = NOW()
               WHERE id = $1
               RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.pattern)
        .bind(&req.action)
        .bind(&req.description)
        .bind(req.enabled)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_bot_pattern(&self, id: i32) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM bot_patterns WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Delete by exact pattern text — what `prx-waf bot remove <pattern>` needs
    /// when the operator has the regex but not the id. Returns the number of
    /// rows removed.
    pub async fn delete_bot_patterns_by_pattern(&self, pattern: &str) -> Result<u64, StorageError> {
        let r = sqlx::query("DELETE FROM bot_patterns WHERE pattern = $1")
            .bind(pattern)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    // ─── Rule overrides ───────────────────────────────────────────────────────

    /// Every operator override, with the host code joined in.
    ///
    /// One query for the whole table: it is bounded by the size of the rule set
    /// an operator has chosen to tune (single digits in practice), and the
    /// engine needs all of it to rebuild its snapshot anyway.
    pub async fn list_rule_overrides(&self) -> Result<Vec<RuleOverride>, StorageError> {
        let rows = sqlx::query_as::<_, RuleOverride>(
            r"SELECT o.id, o.rule_id, o.host_id, h.code AS host_code, o.enabled,
                     o.action_override, o.note, o.created_at, o.updated_at
                FROM rule_overrides o
                LEFT JOIN hosts h ON h.id = o.host_id
               ORDER BY o.rule_id, h.code NULLS FIRST",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Create or replace the override for one `(rule, scope)` pair.
    ///
    /// `Ok(None)` means `req.host_code` names no host — reported rather than
    /// silently written as a *global* override, which is what a plain
    /// `(SELECT id FROM hosts WHERE code = …)` sub-select would have done with a
    /// typo'd host and is the worst possible failure mode for this table.
    ///
    /// The upsert targets both uniqueness rules the schema carries: the
    /// `(rule_id, host_id)` constraint for host-scoped rows and the
    /// `idx_rule_overrides_global` partial index for the global ones (0016).
    pub async fn upsert_rule_override(&self, req: &CreateRuleOverride) -> Result<Option<RuleOverride>, StorageError> {
        let host_id = match req.host_code.as_deref() {
            None => None,
            Some(code) => match self.get_host_by_code(code).await? {
                Some(host) => Some(host.id),
                None => return Ok(None),
            },
        };

        // Two different uniqueness rules cover the two scopes, and `ON CONFLICT`
        // infers an index by matching the target *exactly*: the 0007 table
        // constraint for host-scoped rows, the 0016 partial index — predicate
        // included — for the global ones.
        let conflict = if host_id.is_some() {
            "(rule_id, host_id)"
        } else {
            "(rule_id) WHERE host_id IS NULL"
        };
        let sql = format!(
            r"INSERT INTO rule_overrides (rule_id, host_id, enabled, action_override, note)
                   VALUES ($1, $2, $3, $4, $5)
              ON CONFLICT {conflict} DO UPDATE
                     SET enabled         = EXCLUDED.enabled,
                         action_override = EXCLUDED.action_override,
                         note            = EXCLUDED.note,
                         updated_at      = NOW()
               RETURNING id, rule_id, host_id, NULL::VARCHAR AS host_code, enabled,
                         action_override, note, created_at, updated_at"
        );
        // The only interpolation is the conflict target, chosen from the two
        // string literals above by a boolean — no caller input reaches the SQL
        // text. Every value is bound.
        let mut row = sqlx::query_as::<_, RuleOverride>(&sql)
            .bind(&req.rule_id)
            .bind(host_id)
            .bind(req.enabled)
            .bind(&req.action_override)
            .bind(&req.note)
            .fetch_one(&self.pool)
            .await?;
        row.host_code.clone_from(&req.host_code);
        Ok(Some(row))
    }

    /// Replace the decision an existing override carries. `Ok(None)` when no
    /// row has that id.
    pub async fn update_rule_override(
        &self,
        id: i32,
        req: &UpdateRuleOverride,
    ) -> Result<Option<RuleOverride>, StorageError> {
        let row = sqlx::query_as::<_, RuleOverride>(
            r"UPDATE rule_overrides o
                 SET enabled         = $2,
                     action_override = $3,
                     note            = $4,
                     updated_at      = NOW()
               WHERE o.id = $1
               RETURNING o.id, o.rule_id, o.host_id,
                         (SELECT code FROM hosts h WHERE h.id = o.host_id) AS host_code,
                         o.enabled, o.action_override, o.note, o.created_at, o.updated_at",
        )
        .bind(id)
        .bind(req.enabled)
        .bind(&req.action_override)
        .bind(&req.note)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn delete_rule_override(&self, id: i32) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM rule_overrides WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Hotlink Configs ──────────────────────────────────────────────────────

    pub async fn get_hotlink_config(&self, host_code: &str) -> Result<Option<HotlinkConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, HotlinkConfig>("SELECT * FROM hotlink_configs WHERE host_code = $1")
                .bind(host_code)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn list_hotlink_configs(&self) -> Result<Vec<HotlinkConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, HotlinkConfig>("SELECT * FROM hotlink_configs ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn upsert_hotlink_config(&self, req: UpsertHotlinkConfig) -> Result<HotlinkConfig, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let domains = serde_json::to_value(req.allowed_domains.unwrap_or_default())
            .unwrap_or_else(|_| serde_json::Value::Array(vec![]));
        let row = sqlx::query_as::<_, HotlinkConfig>(
            r"INSERT INTO hotlink_configs (id, host_code, enabled, allow_empty_referer, allowed_domains, redirect_url, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
               ON CONFLICT (host_code) DO UPDATE SET
                 enabled=EXCLUDED.enabled, allow_empty_referer=EXCLUDED.allow_empty_referer,
                 allowed_domains=EXCLUDED.allowed_domains, redirect_url=EXCLUDED.redirect_url,
                 updated_at=NOW()
               RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(req.enabled.unwrap_or(true))
        .bind(req.allow_empty_referer.unwrap_or(true))
        .bind(domains).bind(&req.redirect_url).bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    // ─── LB Backends ─────────────────────────────────────────────────────────

    pub async fn list_lb_backends(&self, host_code: Option<&str>) -> Result<Vec<LbBackend>, StorageError> {
        let rows = match host_code {
            Some(code) => {
                sqlx::query_as::<_, LbBackend>(
                    "SELECT * FROM lb_backends WHERE host_code = $1 ORDER BY weight DESC, created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, LbBackend>("SELECT * FROM lb_backends ORDER BY created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn create_lb_backend(&self, req: CreateLbBackend) -> Result<LbBackend, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let row = sqlx::query_as::<_, LbBackend>(
            r"INSERT INTO lb_backends
               (id, host_code, backend_host, backend_port, weight, enabled, health_check_url, health_check_interval_secs, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *"
        )
        .bind(id).bind(&req.host_code).bind(&req.backend_host).bind(req.backend_port)
        .bind(req.weight.unwrap_or(1)).bind(req.enabled.unwrap_or(true))
        .bind(&req.health_check_url)
        .bind(req.health_check_interval_secs.unwrap_or(30))
        .bind(now)
        .fetch_one(&self.pool).await?;
        Ok(row)
    }

    pub async fn delete_lb_backend(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM lb_backends WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_lb_backend_health(&self, id: Uuid, is_healthy: bool) -> Result<(), StorageError> {
        sqlx::query("UPDATE lb_backends SET is_healthy=$2, last_health_check=NOW(), updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(is_healthy)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 4: Admin Users ─────────────────────────────────────────────────

    pub async fn list_admin_users(&self) -> Result<Vec<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users ORDER BY created_at")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_admin_user_by_id(&self, id: Uuid) -> Result<Option<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn get_admin_user_by_username(&self, username: &str) -> Result<Option<AdminUser>, StorageError> {
        Ok(
            sqlx::query_as::<_, AdminUser>("SELECT * FROM admin_users WHERE username = $1")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_admin_user(
        &self,
        req: CreateAdminUser,
        password_hash: &str,
    ) -> Result<AdminUser, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, AdminUser>(
            r"INSERT INTO admin_users
               (id, username, email, password_hash, role, is_active, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,true,$6,$6) RETURNING *",
        )
        .bind(id)
        .bind(&req.username)
        .bind(&req.email)
        .bind(password_hash)
        .bind(req.role.as_deref().unwrap_or("admin"))
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn update_admin_user_last_login(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE admin_users SET last_login = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn admin_users_count(&self) -> Result<i64, StorageError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM admin_users")
            .fetch_one(&self.pool)
            .await?)
    }

    /// Set (or clear with `None`) the TOTP secret for an admin user.
    pub async fn set_admin_user_totp_secret(&self, id: Uuid, secret: Option<&str>) -> Result<(), StorageError> {
        sqlx::query("UPDATE admin_users SET totp_secret = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(secret)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Enable or disable TOTP enforcement for an admin user.
    pub async fn set_admin_user_totp_enabled(&self, id: Uuid, enabled: bool) -> Result<(), StorageError> {
        sqlx::query("UPDATE admin_users SET totp_enabled = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record the highest TOTP step consumed (replay protection).
    pub async fn update_admin_user_totp_last_step(&self, id: Uuid, step: i64) -> Result<(), StorageError> {
        sqlx::query("UPDATE admin_users SET totp_last_step = $2, updated_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(step)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 4: Refresh Tokens ──────────────────────────────────────────────

    pub async fn create_refresh_token(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<RefreshToken, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, RefreshToken>(
            r"INSERT INTO refresh_tokens
               (id, user_id, token_hash, expires_at, revoked, created_at)
               VALUES ($1,$2,$3,$4,false,$5) RETURNING *",
        )
        .bind(id)
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn get_refresh_token_by_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>, StorageError> {
        Ok(sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn revoke_all_user_tokens(&self, user_id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 4: Statistics ──────────────────────────────────────────────────

    pub async fn get_stats_overview(&self) -> Result<StatsOverview, StorageError> {
        let total_blocked_logs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attack_logs WHERE action = 'block'")
            .fetch_one(&self.pool)
            .await?;
        let total_blocked_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM security_events WHERE action = 'block'")
                .fetch_one(&self.pool)
                .await?;
        let total_blocked = total_blocked_logs + total_blocked_events;

        let total_allowed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attack_logs WHERE action = 'allow'")
            .fetch_one(&self.pool)
            .await?;

        let total_requests = total_blocked + total_allowed;

        let hosts_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts")
            .fetch_one(&self.pool)
            .await?;

        // Top attacking IPs
        let top_ips: Vec<TopEntry> = sqlx::query(
            "SELECT client_ip AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             GROUP BY client_ip \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top triggered rules
        let top_rules: Vec<TopEntry> = sqlx::query(
            "SELECT rule_name AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             GROUP BY rule_name \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top attacking countries (from security_events.geo_info)
        let top_countries: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'country' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top ISPs
        let top_isp_list: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'isp' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'isp' IS NOT NULL AND geo_info->>'isp' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 10",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(StatsOverview {
            total_requests,
            total_blocked,
            total_allowed,
            hosts_count,
            top_ips,
            top_rules,
            top_countries,
            top_isps: top_isp_list,
        })
    }

    pub async fn get_stats_timeseries(
        &self,
        host_code: Option<&str>,
        hours: i64,
    ) -> Result<Vec<TimeSeriesPoint>, StorageError> {
        let rows: Vec<TimeSeriesPoint> = sqlx::query(
            "SELECT \
                date_trunc('hour', created_at) AS ts, \
                COUNT(*)::bigint AS total, \
                COUNT(*) FILTER (WHERE action = 'block')::bigint AS blocked \
             FROM security_events \
             WHERE created_at >= NOW() - make_interval(hours => $1::int) \
               AND ($2::text IS NULL OR host_code = $2) \
             GROUP BY date_trunc('hour', created_at) \
             ORDER BY ts ASC",
        )
        .bind(i32::try_from(hours).unwrap_or(i32::MAX))
        .bind(host_code)
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TimeSeriesPoint {
                ts: row.get("ts"),
                total: row.get("total"),
                blocked: row.get("blocked"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn get_geo_stats(&self) -> Result<GeoStats, StorageError> {
        // Top 20 countries by security event count
        let top_countries: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'country' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top 20 cities
        let top_cities: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'city' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'city' IS NOT NULL AND geo_info->>'city' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Top 20 ISPs
        let top_isps: Vec<TopEntry> = sqlx::query(
            "SELECT geo_info->>'isp' AS entry_key, COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'isp' IS NOT NULL AND geo_info->>'isp' != '' \
             GROUP BY entry_key \
             ORDER BY cnt DESC \
             LIMIT 20",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            TopEntry {
                key: row.get("entry_key"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        // Country distribution with iso_code (for world map visualization)
        let country_distribution: Vec<GeoDistEntry> = sqlx::query(
            "SELECT \
                COALESCE(geo_info->>'iso_code', '') AS iso_code, \
                geo_info->>'country' AS country, \
                COUNT(*)::bigint AS cnt \
             FROM security_events \
             WHERE geo_info->>'country' IS NOT NULL AND geo_info->>'country' != '' \
             GROUP BY iso_code, country \
             ORDER BY cnt DESC \
             LIMIT 200",
        )
        .map(|row: sqlx::postgres::PgRow| {
            use sqlx::Row;
            GeoDistEntry {
                iso_code: row.get("iso_code"),
                country: row.get("country"),
                count: row.get("cnt"),
            }
        })
        .fetch_all(&self.pool)
        .await?;

        Ok(GeoStats {
            top_countries,
            top_cities,
            top_isps,
            country_distribution,
        })
    }

    // `request_stats` retention: previously a standalone, unbatched
    // `delete_old_stats` helper existed here with zero call sites anywhere in
    // the codebase — the exact "wrote a cleanup function, never wired it to a
    // scheduler" bug this module exists to fix. It is superseded by
    // `RetentionTable::RequestStats` through the shared, batched
    // `prune_retention_table` below, rather than resurrected as a second,
    // unbounded, single-statement way to delete from the same table.

    // ─── Phase 4: Notifications ───────────────────────────────────────────────

    pub async fn list_notification_configs(
        &self,
        host_code: Option<&str>,
    ) -> Result<Vec<NotificationConfig>, StorageError> {
        Ok(match host_code {
            Some(code) => {
                sqlx::query_as::<_, NotificationConfig>(
                    "SELECT * FROM notification_configs WHERE host_code = $1 ORDER BY created_at",
                )
                .bind(code)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, NotificationConfig>("SELECT * FROM notification_configs ORDER BY created_at")
                    .fetch_all(&self.pool)
                    .await?
            }
        })
    }

    pub async fn get_notification_config(&self, id: Uuid) -> Result<Option<NotificationConfig>, StorageError> {
        Ok(
            sqlx::query_as::<_, NotificationConfig>("SELECT * FROM notification_configs WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_notification_config(
        &self,
        req: CreateNotificationConfig,
    ) -> Result<NotificationConfig, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, NotificationConfig>(
            r"INSERT INTO notification_configs
               (id, name, host_code, event_type, channel_type, config_json, enabled, rate_limit_secs, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.host_code)
        .bind(&req.event_type)
        .bind(&req.channel_type)
        .bind(&req.config_json)
        .bind(req.enabled.unwrap_or(true))
        .bind(req.rate_limit_secs.unwrap_or(300))
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Update a notification config in place.
    ///
    /// `config_json` is the already-merged, already-encrypted channel config
    /// produced by the API layer (secrets the caller left blank have been
    /// carried over from the stored row); pass `None` to leave it untouched.
    /// Returns `None` when no row with `id` exists.
    pub async fn update_notification_config(
        &self,
        id: Uuid,
        req: &UpdateNotificationConfig,
        config_json: Option<&serde_json::Value>,
    ) -> Result<Option<NotificationConfig>, StorageError> {
        Ok(sqlx::query_as::<_, NotificationConfig>(
            r"UPDATE notification_configs SET
                 name            = COALESCE($2::varchar, name),
                 host_code       = COALESCE($3::varchar, host_code),
                 event_type      = COALESCE($4::varchar, event_type),
                 config_json     = COALESCE($5::jsonb, config_json),
                 enabled         = COALESCE($6::boolean, enabled),
                 rate_limit_secs = COALESCE($7::integer, rate_limit_secs),
                 updated_at      = NOW()
               WHERE id = $1 RETURNING *",
        )
        .bind(id)
        .bind(req.name.as_deref())
        .bind(req.host_code.as_deref())
        .bind(req.event_type.as_deref())
        .bind(config_json)
        .bind(req.enabled)
        .bind(req.rate_limit_secs)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn delete_notification_config(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM notification_configs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_notification_last_triggered(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE notification_configs SET last_triggered = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_enabled_notification_configs(
        &self,
        event_type: &str,
    ) -> Result<Vec<NotificationConfig>, StorageError> {
        Ok(sqlx::query_as::<_, NotificationConfig>(
            "SELECT * FROM notification_configs WHERE event_type = $1 AND enabled = true",
        )
        .bind(event_type)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_notification_log(
        &self,
        config_id: Option<Uuid>,
        event_type: &str,
        channel_type: &str,
        status: &str,
        message: Option<&str>,
        error_msg: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO notification_log
               (id, config_id, event_type, channel_type, status, message, error_msg)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)",
        )
        .bind(config_id)
        .bind(event_type)
        .bind(channel_type)
        .bind(status)
        .bind(message)
        .bind(error_msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_notification_log(&self, limit: i64) -> Result<Vec<NotificationLog>, StorageError> {
        Ok(
            sqlx::query_as::<_, NotificationLog>("SELECT * FROM notification_log ORDER BY created_at DESC LIMIT $1")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn list_security_events(
        &self,
        query: &SecurityEventQuery,
    ) -> Result<(Vec<SecurityEvent>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * page_size;

        let total: i64 = sqlx::query_scalar(
            r"SELECT COUNT(*) FROM security_events
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR rule_name = $3)
                 AND ($4::text IS NULL OR action = $4)
                 AND ($5::text IS NULL OR geo_info->>'iso_code' = $5)
                 AND ($6::text IS NULL OR geo_info->>'country' ILIKE '%' || $6 || '%')",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.rule_name)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, SecurityEvent>(
            r"SELECT * FROM security_events
               WHERE ($1::text IS NULL OR host_code = $1)
                 AND ($2::text IS NULL OR client_ip = $2)
                 AND ($3::text IS NULL OR rule_name = $3)
                 AND ($4::text IS NULL OR action = $4)
                 AND ($5::text IS NULL OR geo_info->>'iso_code' = $5)
                 AND ($6::text IS NULL OR geo_info->>'country' ILIKE '%' || $6 || '%')
               ORDER BY created_at DESC
               LIMIT $7 OFFSET $8",
        )
        .bind(&query.host_code)
        .bind(&query.client_ip)
        .bind(&query.rule_name)
        .bind(&query.action)
        .bind(&query.iso_code)
        .bind(&query.country)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ─── Phase 5: WASM Plugins ────────────────────────────────────────────────

    pub async fn list_wasm_plugins(&self) -> Result<Vec<WasmPluginRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, WasmPluginRow>("SELECT * FROM wasm_plugins ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_wasm_plugin(&self, id: Uuid) -> Result<Option<WasmPluginRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, WasmPluginRow>("SELECT * FROM wasm_plugins WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_wasm_plugin(&self, req: CreateWasmPlugin) -> Result<WasmPluginRow, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, WasmPluginRow>(
            r"INSERT INTO wasm_plugins
               (id, name, version, description, author, wasm_binary, enabled, config_json, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(req.version.as_deref().unwrap_or("1.0.0"))
        .bind(&req.description)
        .bind(&req.author)
        .bind(&req.wasm_binary)
        .bind(req.enabled.unwrap_or(true))
        .bind(
            req.config_json
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::default())),
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn set_wasm_plugin_enabled(&self, id: Uuid, enabled: bool) -> Result<bool, StorageError> {
        let r = sqlx::query("UPDATE wasm_plugins SET enabled=$2, updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn delete_wasm_plugin(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM wasm_plugins WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ─── Phase 5: Tunnels ─────────────────────────────────────────────────────

    pub async fn list_tunnels(&self) -> Result<Vec<TunnelRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn get_tunnel(&self, id: Uuid) -> Result<Option<TunnelRow>, StorageError> {
        Ok(sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn get_tunnel_by_token_hash(&self, token_hash: &str) -> Result<Option<TunnelRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, TunnelRow>("SELECT * FROM tunnels WHERE token_hash = $1 AND enabled = true")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn create_tunnel(&self, req: &CreateTunnel, token_hash: &str) -> Result<TunnelRow, StorageError> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();
        Ok(sqlx::query_as::<_, TunnelRow>(
            r"INSERT INTO tunnels
               (id, name, token_hash, target_host, target_port, enabled, status, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,'disconnected',$7,$7) RETURNING *",
        )
        .bind(id)
        .bind(&req.name)
        .bind(token_hash)
        .bind(&req.target_host)
        .bind(req.target_port)
        .bind(req.enabled.unwrap_or(true))
        .bind(now)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn delete_tunnel(&self, id: Uuid) -> Result<bool, StorageError> {
        let r = sqlx::query("DELETE FROM tunnels WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn update_tunnel_status(&self, id: Uuid, status: &str) -> Result<(), StorageError> {
        let last_seen: Option<chrono::DateTime<chrono::Utc>> = if status == "connected" {
            Some(chrono::Utc::now())
        } else {
            None
        };
        sqlx::query("UPDATE tunnels SET status=$2, last_seen=COALESCE($3, last_seen), updated_at=NOW() WHERE id=$1")
            .bind(id)
            .bind(status)
            .bind(last_seen)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Phase 5: Audit Log ───────────────────────────────────────────────────

    pub async fn create_audit_log(
        &self,
        admin_username: Option<&str>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        detail: Option<serde_json::Value>,
        ip_addr: Option<&str>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO audit_log
               (admin_username, action, resource_type, resource_id, detail, ip_addr)
               VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(admin_username)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(detail)
        .bind(ip_addr)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_audit_log(&self, query: &AuditLogQuery) -> Result<(Vec<AuditLogEntry>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * page_size;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE ($1::text IS NULL OR admin_username = $1)
               AND ($2::text IS NULL OR action = $2)",
        )
        .bind(&query.admin_username)
        .bind(&query.action)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, AuditLogEntry>(
            "SELECT * FROM audit_log
             WHERE ($1::text IS NULL OR admin_username = $1)
               AND ($2::text IS NULL OR action = $2)
             ORDER BY created_at DESC
             LIMIT $3 OFFSET $4",
        )
        .bind(&query.admin_username)
        .bind(&query.action)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ─── Phase 6: CrowdSec ───────────────────────────────────────────────────

    pub async fn get_crowdsec_config(&self) -> Result<Option<CrowdSecConfigRow>, StorageError> {
        Ok(
            sqlx::query_as::<_, CrowdSecConfigRow>("SELECT * FROM crowdsec_config ORDER BY id LIMIT 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn upsert_crowdsec_config(
        &self,
        req: &UpsertCrowdSecConfig,
        api_key_enc: Option<String>,
        appsec_key_enc: Option<String>,
    ) -> Result<CrowdSecConfigRow, StorageError> {
        let now = chrono::Utc::now();
        let freq = req.update_frequency_secs.unwrap_or(10);
        let fallback = req.fallback_action.clone().unwrap_or_else(|| "allow".to_string());

        let row = sqlx::query_as::<_, CrowdSecConfigRow>(
            r"INSERT INTO crowdsec_config
               (host_id, enabled, mode, lapi_url, api_key_encrypted,
                appsec_endpoint, appsec_key_encrypted,
                update_frequency_secs, fallback_action, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
               ON CONFLICT ((COALESCE(host_id, '00000000-0000-0000-0000-000000000000'::uuid))) DO UPDATE SET
                 enabled = EXCLUDED.enabled,
                 mode = EXCLUDED.mode,
                 lapi_url = EXCLUDED.lapi_url,
                 api_key_encrypted = COALESCE(EXCLUDED.api_key_encrypted, crowdsec_config.api_key_encrypted),
                 appsec_endpoint = EXCLUDED.appsec_endpoint,
                 appsec_key_encrypted = COALESCE(EXCLUDED.appsec_key_encrypted, crowdsec_config.appsec_key_encrypted),
                 update_frequency_secs = EXCLUDED.update_frequency_secs,
                 fallback_action = EXCLUDED.fallback_action,
                 updated_at = EXCLUDED.updated_at
               RETURNING *",
        )
        .bind(req.host_id)
        .bind(req.enabled)
        .bind(&req.mode)
        .bind(&req.lapi_url)
        .bind(&api_key_enc)
        .bind(&req.appsec_endpoint)
        .bind(&appsec_key_enc)
        .bind(freq)
        .bind(&fallback)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn log_crowdsec_event(&self, req: &CreateCrowdSecEvent) -> Result<(), StorageError> {
        sqlx::query(
            r"INSERT INTO crowdsec_events
               (host_id, client_ip, decision_type, scenario, action_taken, request_path)
               VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(req.host_id)
        .bind(&req.client_ip)
        .bind(&req.decision_type)
        .bind(&req.scenario)
        .bind(&req.action_taken)
        .bind(&req.request_path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_crowdsec_events(
        &self,
        query: &CrowdSecEventQuery,
    ) -> Result<(Vec<CrowdSecEventRow>, i64), StorageError> {
        let page = query.page.unwrap_or(1).max(1);
        let page_size = query.page_size.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * page_size;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crowdsec_events")
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query_as::<_, CrowdSecEventRow>(
            "SELECT * FROM crowdsec_events ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows, total))
    }

    // ── crowdsec_decisions: durable mirror of the bouncer decision cache ──────
    //
    // `crowdsec_decisions` is a *cache of active decisions*, not a history log
    // (`crowdsec_events` is the history). Nothing read or wrote it before, so a
    // restart with an unreachable LAPI left the in-memory cache empty and the
    // bouncer fail-open until the next successful poll. These four statements
    // are the durable side: the sync task mirrors every decision it caches, and
    // startup restores the still-valid ones before the proxy serves traffic.
    //
    // Conflict key is `id`, the identity LAPI itself assigns. `CrowdSec` reuses
    // decision ids after a LAPI database reset, so keying on `id` makes the
    // reused id *replace* the stale row instead of failing on the primary key.
    // Removal, in contrast, is keyed on `(scope, value)` — the same key the
    // in-memory cache removes on — so a revoked ban can never survive in the
    // mirror and be resurrected by the next restart.

    /// Every decision in the mirror that has not expired yet, skipping rows too
    /// incomplete to describe a decision.
    ///
    /// Filtered in SQL so a mirror holding days of expired rows (the retention
    /// window deliberately keeps them for a while) costs one index range scan
    /// instead of a full table read. Rows with an unknown expiry
    /// (`expires_at IS NULL`, only reachable by hand-inserted rows — the writer
    /// below always supplies one) are skipped: an unknown lifetime cannot be
    /// proven still active, and restoring it would be the resurrection this
    /// mirror exists to avoid. That `IS NOT NULL` is also what lets
    /// [`CrowdSecDecisionRow::expires_at`] stay a non-optional `DateTime`
    /// against a nullable column, so the predicate must not be relaxed.
    ///
    /// The other five nullable text columns get the same protection in Rust
    /// rather than in SQL, because a filtered-out row must be *reported*: see
    /// [`RawCrowdSecDecision`] for why one malformed row may not cost the
    /// caller every other decision.
    pub async fn load_active_crowdsec_decisions(&self) -> Result<Vec<CrowdSecDecisionRow>, StorageError> {
        let raw = sqlx::query_as::<_, RawCrowdSecDecision>(
            "SELECT id, origin, scope, value, type, scenario, duration_secs, expires_at \
               FROM crowdsec_decisions \
              WHERE expires_at IS NOT NULL AND expires_at > NOW()",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut rows = Vec::with_capacity(raw.len());
        let mut skipped = 0usize;
        let mut sample: Vec<String> = Vec::new();
        for row in raw {
            let id = row.id;
            match row.into_decision() {
                Ok(decision) => rows.push(decision),
                Err(missing) => {
                    skipped += 1;
                    if sample.len() < MALFORMED_DECISION_SAMPLE {
                        sample.push(format!("{id} (null: {})", missing.join("+")));
                    }
                }
            }
        }
        if skipped > 0 {
            warn!(
                skipped,
                restored = rows.len(),
                sample = %sample.join(", "),
                "Skipped CrowdSec mirror rows with NULL required columns; the rest of the mirror was restored"
            );
        }
        debug!("Loaded {} active CrowdSec decisions from the local mirror", rows.len());
        Ok(rows)
    }

    /// Insert or refresh `rows`, keyed on the upstream decision id.
    pub async fn upsert_crowdsec_decisions(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.pool.acquire().await?;
        let mut affected = 0u64;
        for chunk in rows.chunks(CROWDSEC_DECISION_CHUNK) {
            affected += upsert_crowdsec_decision_chunk(&mut *conn, chunk).await?;
        }
        Ok(affected)
    }

    /// Remove every mirrored decision whose `(scope, value)` appears in `keys`.
    ///
    /// Keyed on the banned value rather than the decision id so the mirror
    /// tracks the in-memory cache exactly: the cache also removes by value, and
    /// a value the cache has released must not come back on the next restart.
    pub async fn delete_crowdsec_decisions(&self, keys: &[(String, String)]) -> Result<u64, StorageError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let mut conn = self.pool.acquire().await?;
        let mut affected = 0u64;
        for chunk in keys.chunks(CROWDSEC_DECISION_CHUNK) {
            let scopes: Vec<&str> = chunk.iter().map(|(scope, _)| scope.as_str()).collect();
            let values: Vec<&str> = chunk.iter().map(|(_, value)| value.as_str()).collect();
            affected += sqlx::query(
                "DELETE FROM crowdsec_decisions \
                  WHERE (scope, value) IN (SELECT * FROM UNNEST($1::text[], $2::text[]))",
            )
            .bind(&scopes)
            .bind(&values)
            .execute(&mut *conn)
            .await?
            .rows_affected();
        }
        Ok(affected)
    }

    /// Make the mirror hold exactly `rows` and nothing else, atomically.
    ///
    /// Called after a **full** LAPI pull (`startup=true`), which returns the
    /// complete active decision set. Rows absent from that set were revoked
    /// while this process was down or was not listening, so they are deleted in
    /// the same transaction that upserts the survivors — the guarantee that a
    /// lifted ban is never resurrected by a later restart.
    ///
    /// An empty `rows` therefore empties the table: "LAPI has no active
    /// decisions" is a real answer, not a missing one.
    pub async fn replace_crowdsec_decisions(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
        let mut tx = self.pool.begin().await?;
        for chunk in rows.chunks(CROWDSEC_DECISION_CHUNK) {
            upsert_crowdsec_decision_chunk(&mut *tx, chunk).await?;
        }
        let keep: Vec<i64> = rows.iter().map(|row| row.id).collect();
        let removed = sqlx::query("DELETE FROM crowdsec_decisions WHERE NOT (id = ANY($1::bigint[]))")
            .bind(&keep)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(removed)
    }
}

/// Rows per `crowdsec_decisions` statement.
///
/// A full LAPI pull can carry tens of thousands of decisions (CAPI blocklists
/// alone are that large). One statement per chunk keeps each parameter array —
/// and each row lock hold — bounded, while still costing only a handful of
/// round-trips for a realistic decision set.
const CROWDSEC_DECISION_CHUNK: usize = 1_000;

/// How many malformed decision ids the skip warning names before it stops.
///
/// A table that is wholly corrupt must produce a log line an operator can read,
/// not one row of text per mirrored decision. The count is always exact; only
/// the id list is capped.
const MALFORMED_DECISION_SAMPLE: usize = 10;

/// A `crowdsec_decisions` row as the *schema* permits it, not as the writer
/// produces it.
///
/// `migrations/0006_crowdsec.sql:22-26` leaves `origin`, `scope`, `value`,
/// `type` and `scenario` nullable. [`upsert_crowdsec_decision_chunk`] never
/// writes `NULL` into any of them, so only a hand-inserted row, a restored
/// dump, or third-party tooling writing to the same table can produce one — and
/// this table is documented as a *cache*, which invites exactly that.
///
/// Decoding such a row straight into [`CrowdSecDecisionRow`]'s non-optional
/// `String` fields raises `UnexpectedNullError`, and because the read is a
/// `fetch_all` that error fails the **whole** load. The whole load is the
/// bouncer's startup cache restore, whose entire purpose is to keep the process
/// from failing open when LAPI is unreachable at boot. Letting one unusable row
/// discard every usable one would disable that protection at precisely the
/// moment it is needed, so the incomplete rows are dropped, counted and
/// reported instead, and every well-formed decision is still restored.
#[derive(sqlx::FromRow)]
struct RawCrowdSecDecision {
    id: i64,
    origin: Option<String>,
    scope: Option<String>,
    value: Option<String>,
    #[sqlx(rename = "type")]
    type_: Option<String>,
    scenario: Option<String>,
    duration_secs: Option<i64>,
    expires_at: DateTime<Utc>,
}

impl RawCrowdSecDecision {
    /// The decision this row describes, or the names of the columns whose
    /// `NULL` left it undescribable.
    fn into_decision(self) -> Result<CrowdSecDecisionRow, Vec<&'static str>> {
        let Self {
            id,
            origin,
            scope,
            value,
            type_,
            scenario,
            duration_secs,
            expires_at,
        } = self;
        match (origin, scope, value, type_, scenario) {
            (Some(origin), Some(scope), Some(value), Some(type_), Some(scenario)) => Ok(CrowdSecDecisionRow {
                id,
                origin,
                scope,
                value,
                type_,
                scenario,
                duration_secs,
                expires_at,
            }),
            (origin, scope, value, type_, scenario) => {
                let mut missing = Vec::new();
                if origin.is_none() {
                    missing.push("origin");
                }
                if scope.is_none() {
                    missing.push("scope");
                }
                if value.is_none() {
                    missing.push("value");
                }
                if type_.is_none() {
                    missing.push("type");
                }
                if scenario.is_none() {
                    missing.push("scenario");
                }
                Err(missing)
            }
        }
    }
}

/// One bulk upsert of `chunk` into `crowdsec_decisions`.
///
/// Columns are passed as parallel arrays through `UNNEST`, so the statement
/// text is fixed and every value is a bind parameter regardless of batch size.
///
/// The caller must have de-duplicated `chunk` by `id`: Postgres rejects an
/// `ON CONFLICT DO UPDATE` that would touch the same row twice in one
/// statement.
async fn upsert_crowdsec_decision_chunk<'e, E>(executor: E, chunk: &[CrowdSecDecisionRow]) -> Result<u64, StorageError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let ids: Vec<i64> = chunk.iter().map(|row| row.id).collect();
    let origins: Vec<&str> = chunk.iter().map(|row| row.origin.as_str()).collect();
    let scopes: Vec<&str> = chunk.iter().map(|row| row.scope.as_str()).collect();
    let values: Vec<&str> = chunk.iter().map(|row| row.value.as_str()).collect();
    let types: Vec<&str> = chunk.iter().map(|row| row.type_.as_str()).collect();
    let scenarios: Vec<&str> = chunk.iter().map(|row| row.scenario.as_str()).collect();
    let durations: Vec<Option<i64>> = chunk.iter().map(|row| row.duration_secs).collect();
    let expiries: Vec<DateTime<Utc>> = chunk.iter().map(|row| row.expires_at).collect();

    let affected = sqlx::query(
        "INSERT INTO crowdsec_decisions (id, origin, scope, value, type, scenario, duration_secs, expires_at) \
         SELECT * FROM UNNEST($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], \
                              $7::bigint[], $8::timestamptz[]) \
         ON CONFLICT (id) DO UPDATE SET \
             origin = EXCLUDED.origin, \
             scope = EXCLUDED.scope, \
             value = EXCLUDED.value, \
             type = EXCLUDED.type, \
             scenario = EXCLUDED.scenario, \
             duration_secs = EXCLUDED.duration_secs, \
             expires_at = EXCLUDED.expires_at",
    )
    .bind(&ids)
    .bind(&origins)
    .bind(&scopes)
    .bind(&values)
    .bind(&types)
    .bind(&scenarios)
    .bind(&durations)
    .bind(&expiries)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(affected)
}
