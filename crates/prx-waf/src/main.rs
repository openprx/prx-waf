use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use gateway::{HostRouter, TunnelConfig, WafProxy};
use waf_api::{start_api_server, AppState};
use waf_common::config::{load_config, AppConfig};
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;

/// PRX-WAF — High-performance Pingora-based Web Application Firewall
#[derive(Parser, Debug)]
#[command(name = "prx-waf", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/default.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the proxy and management API
    Run,
    /// Run database migrations only
    Migrate,
    /// Seed the default admin user (admin / admin) if none exist
    SeedAdmin,
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    info!("PRX-WAF v{}", env!("CARGO_PKG_VERSION"));

    let config = load_config(&cli.config).unwrap_or_else(|e| {
        tracing::warn!(
            "Failed to load config from {}: {}. Using defaults.",
            cli.config,
            e
        );
        AppConfig::default()
    });

    match cli.command {
        Commands::Migrate => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_migrate(&config))?;
        }
        Commands::SeedAdmin => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_seed_admin(&config))?;
        }
        Commands::Run => {
            run_server(config)?;
        }
    }

    Ok(())
}

/// Run database migrations only
async fn run_migrate(config: &AppConfig) -> anyhow::Result<()> {
    info!("Running database migrations...");
    let db =
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    db.migrate().await?;
    info!("Migrations complete.");
    Ok(())
}

/// Seed the default admin user
async fn run_seed_admin(config: &AppConfig) -> anyhow::Result<()> {
    info!("Connecting to database...");
    let db = Arc::new(
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?,
    );
    db.migrate().await?;

    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let state = Arc::new(AppState::new(Arc::clone(&db), engine, router));

    waf_api::auth::ensure_default_admin(&state).await?;
    info!("Default admin user seeded (username=admin, password=admin). Change it immediately!");
    Ok(())
}

/// Start the full server: async init → API server thread → Pingora proxy
fn run_server(config: AppConfig) -> anyhow::Result<()> {
    use pingora_core::server::Server;

    // Async initialization (db, engine, rules, Phase 5 components)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let (engine, router, api_state) = rt.block_on(init_async(&config))?;

    // Start the management API in a background thread
    let api_listen = config.api.listen_addr.clone();
    let api_state_bg = Arc::clone(&api_state);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build API runtime");
        rt.block_on(async move {
            if let Err(e) = start_api_server(&api_listen, api_state_bg).await {
                tracing::error!("API server error: {}", e);
            }
        });
    });

    // Optionally start HTTP/3 listener
    if config.http3.enabled {
        let h3_config = config.http3.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build HTTP/3 runtime");
            rt.block_on(async move {
                let cert_pem = match h3_config.cert_pem.as_deref() {
                    Some(p) => match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => { tracing::error!("HTTP/3 cert read error: {e}"); return; }
                    },
                    None => { tracing::error!("HTTP/3 cert_pem not configured"); return; }
                };
                let key_pem = match h3_config.key_pem.as_deref() {
                    Some(p) => match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => { tracing::error!("HTTP/3 key read error: {e}"); return; }
                    },
                    None => { tracing::error!("HTTP/3 key_pem not configured"); return; }
                };
                let addr: std::net::SocketAddr = match h3_config.listen_addr.parse() {
                    Ok(a) => a,
                    Err(e) => { tracing::error!("HTTP/3 listen_addr parse error: {e}"); return; }
                };
                if let Err(e) = gateway::http3::start_http3_server(
                    addr,
                    cert_pem,
                    key_pem,
                    "http://127.0.0.1:8080".to_string(),
                )
                .await
                {
                    tracing::error!("HTTP/3 server error: {e}");
                }
            });
        });
    }

    // Build and run Pingora proxy (blocks forever)
    let mut server = Server::new(None)?;
    server.bootstrap();

    let proxy = WafProxy::new(router, engine);
    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen_addr);
    server.add_service(proxy_service);

    info!("Proxy listening on {}", config.proxy.listen_addr);
    info!("Management API listening on {}", config.api.listen_addr);
    if config.http3.enabled {
        info!("HTTP/3 (QUIC) listener on {}", config.http3.listen_addr);
    }
    info!("Press Ctrl+C to stop");

    server.run_forever();
}

/// Async initialization: database, engine, rule loading, Phase 5 components
async fn init_async(
    config: &AppConfig,
) -> anyhow::Result<(Arc<WafEngine>, Arc<HostRouter>, Arc<AppState>)> {
    info!("Connecting to database...");
    let db = Arc::new(
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?,
    );

    info!("Running database migrations...");
    db.migrate().await?;

    // WAF engine
    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    engine.reload_rules().await?;

    // Host router
    let router = Arc::new(HostRouter::new());

    // Load hosts from database
    let hosts = db.list_hosts().await?;
    info!("Loading {} hosts from database", hosts.len());
    for host in &hosts {
        use waf_common::HostConfig;
        let cfg = Arc::new(HostConfig {
            code: host.code.clone(),
            host: host.host.clone(),
            port: host.port as u16,
            ssl: host.ssl,
            guard_status: host.guard_status,
            remote_host: host.remote_host.clone(),
            remote_port: host.remote_port as u16,
            remote_ip: host.remote_ip.clone(),
            cert_file: host.cert_file.clone(),
            key_file: host.key_file.clone(),
            start_status: host.start_status,
            ..HostConfig::default()
        });
        router.register(cfg);
    }

    // Register hosts from config file
    for entry in &config.hosts {
        use waf_common::HostConfig;
        let code = format!(
            "cfg-{}",
            &uuid::Uuid::new_v4().to_string().replace('-', "")[..8]
        );
        let cfg = Arc::new(HostConfig {
            code,
            host: entry.host.clone(),
            port: entry.port,
            ssl: entry.ssl.unwrap_or(false),
            guard_status: entry.guard_status.unwrap_or(true),
            remote_host: entry.remote_host.clone(),
            remote_port: entry.remote_port,
            cert_file: entry.cert_file.clone(),
            key_file: entry.key_file.clone(),
            ..HostConfig::default()
        });
        router.register(cfg);
    }

    info!("Registered {} host routes", router.len());

    // Build app state
    let api_state = Arc::new(AppState::new(
        Arc::clone(&db),
        Arc::clone(&engine),
        Arc::clone(&router),
    ));

    // Phase 4: create default admin user if none exist
    if let Err(e) = waf_api::auth::ensure_default_admin(&api_state).await {
        tracing::warn!("Could not ensure default admin: {e}");
    }

    // Phase 5: load WASM plugins from DB
    let plugins = db.list_wasm_plugins().await.unwrap_or_default();
    info!("Loading {} WASM plugins", plugins.len());
    for p in &plugins {
        if let Err(e) = api_state
            .plugin_manager
            .load(
                p.id,
                p.name.clone(),
                p.version.clone(),
                p.description.clone().unwrap_or_default(),
                p.author.clone().unwrap_or_default(),
                p.enabled,
                &p.wasm_binary,
            )
            .await
        {
            tracing::warn!(plugin = %p.name, "Failed to load plugin: {e}");
        }
    }

    // Phase 5: load tunnel configs from DB
    let tunnels = db.list_tunnels().await.unwrap_or_default();
    info!("Loaded {} tunnel configs", tunnels.len());
    for t in &tunnels {
        api_state.tunnel_registry.register(TunnelConfig {
            id: t.id,
            name: t.name.clone(),
            token_hash: t.token_hash.clone(),
            target_host: t.target_host.clone(),
            target_port: t.target_port as u16,
            enabled: t.enabled,
        }).await;
    }

    Ok((engine, router, api_state))
}
