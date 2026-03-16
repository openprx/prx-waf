use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use gateway::{HostRouter, TunnelConfig, WafProxy};
use waf_api::{start_api_server, AppState};
use waf_common::config::{load_config, AppConfig};
use waf_engine::{init_crowdsec, CrowdSecClient, CrowdSecConfig, WafEngine, WafEngineConfig};
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
    /// CrowdSec integration management
    #[command(subcommand)]
    Crowdsec(CrowdSecCommands),
}

/// CrowdSec sub-commands
#[derive(Subcommand, Debug)]
enum CrowdSecCommands {
    /// Show CrowdSec connection status and cache statistics
    Status,
    /// List active decisions cached from LAPI
    Decisions,
    /// Test LAPI connectivity
    Test,
    /// Interactive setup wizard (detect platform, generate config snippet)
    Setup,
}

fn main() -> anyhow::Result<()> {
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
        Commands::Crowdsec(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_crowdsec_cmd(sub, &config))?;
        }
    }

    Ok(())
}

async fn run_migrate(config: &AppConfig) -> anyhow::Result<()> {
    info!("Running database migrations...");
    let db =
        Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    db.migrate().await?;
    info!("Migrations complete.");
    Ok(())
}

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

/// Handle CrowdSec CLI sub-commands
async fn run_crowdsec_cmd(cmd: CrowdSecCommands, config: &AppConfig) -> anyhow::Result<()> {
    let cs_config = app_config_to_crowdsec(config);

    match cmd {
        CrowdSecCommands::Status => {
            println!("CrowdSec Integration Status");
            println!("  Enabled : {}", cs_config.enabled);
            println!("  Mode    : {:?}", cs_config.mode);
            println!("  LAPI URL: {}", cs_config.lapi_url);
            if !cs_config.enabled {
                println!("\n  [INFO] CrowdSec is disabled. Enable it in configs/default.toml.");
            }
        }

        CrowdSecCommands::Decisions => {
            if !cs_config.enabled {
                println!("CrowdSec is not enabled.");
                return Ok(());
            }
            let client =
                CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            let stream = client.get_decisions_stream(true).await?;
            let decisions = stream.new.unwrap_or_default();
            println!("Active decisions ({}):", decisions.len());
            println!(
                "{:<18} {:<12} {:<40} {:<12} {}",
                "Value", "Type", "Scenario", "Origin", "Duration"
            );
            println!("{}", "-".repeat(100));
            for d in &decisions {
                println!(
                    "{:<18} {:<12} {:<40} {:<12} {}",
                    d.value,
                    d.type_,
                    d.scenario,
                    d.origin,
                    d.duration.as_deref().unwrap_or("-"),
                );
            }
        }

        CrowdSecCommands::Test => {
            if cs_config.api_key.is_empty() {
                println!("ERROR: No API key configured. Check your config file.");
                return Ok(());
            }
            println!("Testing connection to: {}", cs_config.lapi_url);
            let client =
                CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            match client.test_connection().await {
                Ok(msg) => println!("OK: {}", msg),
                Err(e) => println!("FAILED: {}", e),
            }
        }

        CrowdSecCommands::Setup => {
            println!("CrowdSec Setup Wizard");
            println!("=====================");
            println!();

            #[cfg(target_os = "linux")]
            {
                println!("Detected platform: Linux");
                let lapi_cfg = std::path::Path::new("/etc/crowdsec/local_api_credentials.yaml");
                if lapi_cfg.exists() {
                    println!("Found CrowdSec LAPI credentials at: {}", lapi_cfg.display());
                } else {
                    println!("CrowdSec config not found. Install CrowdSec first:");
                    println!("  curl -s https://install.crowdsec.net | sudo sh");
                }
                println!();
                println!("To create a bouncer API key:");
                println!("  sudo cscli bouncers add prx-waf-bouncer");
                println!();
            }
            #[cfg(target_os = "windows")]
            {
                println!("Detected platform: Windows");
                println!("CrowdSec for Windows: https://docs.crowdsec.net/docs/getting_started/install_windows/");
                println!();
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            {
                println!("Detected platform: Unix/macOS (Docker recommended)");
                println!("  docker run -d crowdsecurity/crowdsec");
                println!();
            }

            println!("Add to your configs/default.toml:");
            println!();
            println!("[crowdsec]");
            println!("enabled = true");
            println!("mode = \"bouncer\"          # bouncer | appsec | both");
            println!("lapi_url = \"http://127.0.0.1:8080\"");
            println!("api_key = \"<paste your bouncer key here>\"");
            println!("update_frequency_secs = 10");
            println!("fallback_action = \"allow\"  # allow | block | log");
        }
    }

    Ok(())
}

/// Convert the flat AppConfig CrowdSecConfig to the engine's CrowdSecConfig type.
fn app_config_to_crowdsec(config: &AppConfig) -> CrowdSecConfig {
    use waf_engine::crowdsec::config::{AppSecConfig, CrowdSecMode, FallbackAction, PusherConfig};

    let mode = match config.crowdsec.mode.as_str() {
        "appsec" => CrowdSecMode::Appsec,
        "both" => CrowdSecMode::Both,
        _ => CrowdSecMode::Bouncer,
    };

    let fallback = match config.crowdsec.fallback_action.as_str() {
        "block" => FallbackAction::Block,
        "log" => FallbackAction::Log,
        _ => FallbackAction::Allow,
    };

    let appsec = config
        .crowdsec
        .appsec_endpoint
        .as_ref()
        .map(|endpoint| AppSecConfig {
            endpoint: endpoint.clone(),
            api_key: config.crowdsec.appsec_key.clone().unwrap_or_default(),
            timeout_ms: config.crowdsec.appsec_timeout_ms,
            failure_action: FallbackAction::Allow,
        });

    let pusher = config
        .crowdsec
        .pusher_login
        .as_ref()
        .zip(config.crowdsec.pusher_password.as_ref())
        .map(|(login, password)| PusherConfig {
            login: login.clone(),
            password: password.clone(),
        });

    CrowdSecConfig {
        enabled: config.crowdsec.enabled,
        mode,
        lapi_url: config.crowdsec.lapi_url.clone(),
        api_key: config.crowdsec.api_key.clone(),
        update_frequency_secs: config.crowdsec.update_frequency_secs,
        cache_ttl_secs: config.crowdsec.cache_ttl_secs,
        fallback_action: fallback,
        scenarios_containing: config.crowdsec.scenarios_containing.clone(),
        scenarios_not_containing: config.crowdsec.scenarios_not_containing.clone(),
        appsec,
        pusher,
    }
}

/// Start the full server: async init → API server thread → Pingora proxy
fn run_server(config: AppConfig) -> anyhow::Result<()> {
    use pingora_core::server::Server;

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
                        Err(e) => {
                            tracing::error!("HTTP/3 cert read error: {e}");
                            return;
                        }
                    },
                    None => {
                        tracing::error!("HTTP/3 cert_pem not configured");
                        return;
                    }
                };
                let key_pem = match h3_config.key_pem.as_deref() {
                    Some(p) => match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("HTTP/3 key read error: {e}");
                            return;
                        }
                    },
                    None => {
                        tracing::error!("HTTP/3 key_pem not configured");
                        return;
                    }
                };
                let addr: std::net::SocketAddr = match h3_config.listen_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("HTTP/3 listen_addr parse error: {e}");
                        return;
                    }
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

/// Async initialization: database, engine, rules, Phases 5 & 6
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
    let mut api_state = AppState::new(Arc::clone(&db), Arc::clone(&engine), Arc::clone(&router));

    // Phase 4: create default admin user if none exist
    {
        let tmp_state = Arc::new(api_state.clone());
        if let Err(e) = waf_api::auth::ensure_default_admin(&tmp_state).await {
            tracing::warn!("Could not ensure default admin: {e}");
        }
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
        api_state
            .tunnel_registry
            .register(TunnelConfig {
                id: t.id,
                name: t.name.clone(),
                token_hash: t.token_hash.clone(),
                target_host: t.target_host.clone(),
                target_port: t.target_port as u16,
                enabled: t.enabled,
            })
            .await;
    }

    // Phase 6: CrowdSec integration
    let cs_config = app_config_to_crowdsec(config);
    if cs_config.enabled {
        // Create a channel for graceful shutdown signal
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        // Keep _shutdown_tx alive for the process lifetime by leaking it
        std::mem::forget(_shutdown_tx);

        match init_crowdsec(cs_config.clone(), shutdown_rx).await {
            Some(components) => {
                info!(
                    lapi_url = %cs_config.lapi_url,
                    "CrowdSec integration active"
                );

                // Plug bouncer checker and AppSec client into the WAF engine
                engine.set_crowdsec(
                    Arc::clone(&components.checker),
                    components.appsec_client.clone(),
                );

                // Share cache and client with the API layer
                api_state.crowdsec_cache = Some(Arc::clone(&components.cache));
                api_state.crowdsec_client = Some(Arc::clone(&components.lapi_client));
                api_state.crowdsec_lapi_url = Some(cs_config.lapi_url.clone());

                // Keep the background task alive (leaked intentionally — lives until process exit)
                std::mem::forget(components);
            }
            None => {
                tracing::warn!("CrowdSec enabled in config but failed to initialise");
            }
        }
    }

    Ok((engine, router, Arc::new(api_state)))
}
