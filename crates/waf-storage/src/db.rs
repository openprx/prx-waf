use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::broadcast;
use tracing::info;

use crate::StorageError;

/// Database connection wrapper with real-time event broadcast
#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    /// Broadcast channel for real-time security event streaming (WebSocket)
    event_tx: broadcast::Sender<serde_json::Value>,
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

        Ok(Self { pool, event_tx })
    }

    /// Run embedded migrations
    pub async fn migrate(&self) -> Result<(), StorageError> {
        info!("Running database migrations");
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        info!("Migrations completed");
        Ok(())
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Subscribe to real-time security events (for WebSocket streaming)
    pub fn subscribe_events(&self) -> broadcast::Receiver<serde_json::Value> {
        self.event_tx.subscribe()
    }

    /// Broadcast a security event to all WebSocket subscribers
    pub(crate) fn broadcast_event(&self, event: serde_json::Value) {
        let _ = self.event_tx.send(event);
    }
}

/// Strip password from URL for logging
fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.rfind('@')
        && let Some(scheme_end) = url.find("://")
    {
        let scheme = &url[..scheme_end + 3];
        let rest = &url[at_pos..];
        return format!("{}***{}", scheme, rest);
    }
    url.to_string()
}
