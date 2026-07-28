use std::sync::Arc;
use std::sync::OnceLock;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::broadcast;
use tracing::info;
use waf_common::metrics;
use waf_common::notify::{NotificationBus, NotificationEvent};

use crate::StorageError;

/// How often [`Database::spawn_pool_gauge_sampler`] republishes pool occupancy.
const POOL_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Database connection wrapper with real-time event broadcast
#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    /// Broadcast channel for real-time security event streaming (WebSocket)
    event_tx: broadcast::Sender<serde_json::Value>,
    /// Operator-notification bus, installed once at startup by the binary.
    ///
    /// `OnceLock` rather than a constructor parameter because the bus consumer
    /// needs the `AppState` that is itself built from this `Arc<Database>`, so
    /// the two cannot be created in one order. Set-once, then read lock-free on
    /// every write path. Unset (unit tests, tooling) makes every publish a
    /// no-op.
    notification_bus: OnceLock<Arc<NotificationBus>>,
}

impl Database {
    /// Create a new database connection pool
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        info!("Connecting to PostgreSQL: {}", sanitize_url(database_url));

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;

        let (event_tx, _) = broadcast::channel(1024);

        Ok(Self {
            pool,
            event_tx,
            notification_bus: OnceLock::new(),
        })
    }

    /// Run embedded migrations
    pub async fn migrate(&self) -> Result<(), StorageError> {
        info!("Running database migrations");
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        info!("Migrations completed");
        Ok(())
    }

    /// Get a reference to the connection pool
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Publish the pool's occupancy into `prxwaf_db_pool` once.
    ///
    /// Separate from the sampler loop so a test can drive one observation
    /// without a timer, and so the shape of what is published lives next to the
    /// pool it is read from.
    pub fn sample_pool_gauges(&self) {
        // `size()` and `num_idle()` are `u32`/`usize`; both are bounded by
        // `storage.max_connections`, so the conversion cannot lose anything —
        // but it is done saturating rather than with a cast, because a metric
        // that silently wraps is worse than one that is pinned at its maximum.
        metrics::set_pool_gauge(metrics::PoolGauge::Connections, i64::from(self.pool.size()));
        metrics::set_pool_gauge(
            metrics::PoolGauge::Idle,
            i64::try_from(self.pool.num_idle()).unwrap_or(i64::MAX),
        );
    }

    /// Spawn the background sampler that keeps `prxwaf_db_pool` current.
    ///
    /// Pool occupancy is a level, not an event: there is no record site to hang
    /// it off, so something has to read it on a clock. One second is chosen
    /// against the scrape interval — fast enough that a 15 s Prometheus scrape
    /// never reads a value older than it, slow enough to be free (two atomic
    /// loads and two atomic stores per second).
    ///
    /// Returns the join handle; the caller decides its lifetime. The task holds
    /// a `Weak`, so it stops on its own once the last `Arc<Database>` is gone
    /// rather than keeping the pool alive for the life of the process.
    pub fn spawn_pool_gauge_sampler(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POOL_SAMPLE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(db) = weak.upgrade() else {
                    return;
                };
                db.sample_pool_gauges();
            }
        })
    }

    /// Subscribe to real-time security events (for WebSocket streaming)
    pub fn subscribe_events(&self) -> broadcast::Receiver<serde_json::Value> {
        self.event_tx.subscribe()
    }

    /// Broadcast a security event to all WebSocket subscribers
    pub(crate) fn broadcast_event(&self, event: serde_json::Value) {
        let _ = self.event_tx.send(event);
    }

    /// Install the operator-notification bus. Returns `false` if one was
    /// already installed (the bus is set exactly once, at startup).
    pub fn set_notification_bus(&self, bus: Arc<NotificationBus>) -> bool {
        self.notification_bus.set(bus).is_ok()
    }

    /// Publish an operator-notification event, if a bus is installed.
    ///
    /// A bounded, non-blocking `try_send` — safe to call from any write path.
    pub(crate) fn publish_notification(&self, event: NotificationEvent) {
        if let Some(bus) = self.notification_bus.get() {
            bus.publish(event);
        }
    }
}

/// Strip password from URL for logging
fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.rfind('@')
        && let Some(scheme_end) = url.find("://")
    {
        let scheme = &url[..scheme_end + 3];
        let rest = &url[at_pos..];
        return format!("{scheme}***{rest}");
    }
    url.to_string()
}
