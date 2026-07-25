#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use gateway::{
    ChallengeStore, HostRouter, LoadBalancer, LoadBalancerRegistry, ResponseCache, SslManager, TunnelConfig, WafProxy,
    spawn_health_checker,
};
use waf_api::{AppState, start_api_server};
use waf_common::config::{ApiConfig, AppConfig, ConfigError, SecurityConfig, apply_env_overrides, load_config};
use waf_engine::checks::ResponseCheckSet;
use waf_engine::{
    CrowdSecClient, CrowdSecConfig, EnforcementMode, ExportFormat, GeoIpService, IpFeedFormat, IpFeedSource,
    RuleManager, RuntimeContentSecurityConfig, WafEngine, WafEngineConfig, XdbUpdater, cache_policy_from_str,
    init_community, init_crowdsec, spawn_auto_updater, spawn_ip_feed_sync,
};
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
    /// `CrowdSec` integration management
    #[command(subcommand)]
    Crowdsec(CrowdSecCommands),
    /// Rule management (list, validate, reload, import, export, …)
    #[command(subcommand)]
    Rules(RulesCommands),
    /// Rule source management (add, remove, sync, …)
    #[command(subcommand)]
    Sources(SourcesCommands),
    /// Bot detection management (list, add, remove, test)
    #[command(subcommand)]
    Bot(BotCommands),
    /// `GeoIP` database management (download, update, status)
    #[command(subcommand)]
    Geoip(GeoIpCommands),
    /// Community threat intelligence sharing management
    #[command(subcommand)]
    Community(CommunityCommands),
    /// Cluster management (status, nodes, token, promote/demote/remove)
    #[command(subcommand)]
    Cluster(ClusterCommands),
}

// ── Community sub-commands ────────────────────────────────────────────────────

/// Community threat intelligence sub-commands
#[derive(Subcommand, Debug)]
enum CommunityCommands {
    /// Show community integration status
    Status,
    /// Enroll this machine with the community server
    Enroll,
    /// Test connectivity to the community server
    Test,
}

// ── Cluster sub-commands ──────────────────────────────────────────────────────

/// Cluster management sub-commands
#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Show cluster status (role, term, nodes, health)
    Status,
    /// List cluster nodes and their roles
    Nodes,
    /// Cluster join-token management
    #[command(subcommand)]
    Token(ClusterTokenCommands),
    /// Promote a node to Main
    Promote {
        /// Node ID to promote
        node_id: String,
    },
    /// Demote a node to Worker
    Demote {
        /// Node ID to demote
        node_id: String,
    },
    /// Remove a node from the cluster
    Remove {
        /// Node ID to remove
        node_id: String,
    },
    /// Generate cluster CA and per-node certificates for offline provisioning
    ///
    /// Run this once before starting a new cluster. The generated certificates
    /// are written to `OUTPUT_DIR` and then mounted into each node's container.
    CertInit {
        /// Comma-separated list of node names to generate certificates for
        #[arg(long, default_value = "node-a,node-b,node-c")]
        nodes: String,
        /// Output directory for certificate files
        #[arg(long, default_value = "/certs")]
        output_dir: String,
        /// CA certificate validity in days
        #[arg(long, default_value_t = 3650)]
        ca_validity_days: u32,
        /// Node certificate validity in days
        #[arg(long, default_value_t = 365)]
        node_validity_days: u32,
    },
}

/// Cluster token sub-commands
#[derive(Subcommand, Debug)]
enum ClusterTokenCommands {
    /// Generate a cluster join token
    Generate {
        /// Token validity duration (e.g. 24h, 7d)
        #[arg(long, default_value = "24h")]
        ttl: String,
    },
}

// ── CrowdSec sub-commands ─────────────────────────────────────────────────────

/// `CrowdSec` sub-commands
#[derive(Subcommand, Debug)]
enum CrowdSecCommands {
    /// Show `CrowdSec` connection status and cache statistics
    Status,
    /// List active decisions cached from LAPI
    Decisions,
    /// Test LAPI connectivity
    Test,
    /// Interactive setup wizard (detect platform, generate config snippet)
    Setup,
}

// ── Rules sub-commands ────────────────────────────────────────────────────────

/// Rule management sub-commands
#[derive(Subcommand, Debug)]
enum RulesCommands {
    /// List all loaded rules
    List {
        /// Filter by category (sqli, xss, rce, bot, scanner, …)
        #[arg(long)]
        category: Option<String>,
        /// Filter by source (owasp, builtin-bot, builtin-scanner, custom, …)
        #[arg(long)]
        source: Option<String>,
    },
    /// Show detailed information about a rule
    Info {
        /// Rule id
        rule_id: String,
    },
    /// Enable a rule
    Enable {
        /// Rule id
        rule_id: String,
    },
    /// Disable a rule
    Disable {
        /// Rule id
        rule_id: String,
    },
    /// Hot-reload all rules from disk
    Reload,
    /// Validate a rule file without loading it
    Validate {
        /// Path to the rule file
        path: PathBuf,
    },
    /// Import rules from a local file or remote URL
    Import {
        /// File path or HTTP(S) URL
        source: String,
    },
    /// Export current rules to stdout
    Export {
        /// Output format: yaml (default) or json
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    /// Fetch latest rules from all configured remote sources
    Update,
    /// Search rules by name, id, or description
    Search {
        /// Search query
        query: String,
    },
    /// Show rule statistics
    Stats,
}

// ── Sources sub-commands ──────────────────────────────────────────────────────

/// Rule source sub-commands
#[derive(Subcommand, Debug)]
enum SourcesCommands {
    /// List configured rule sources
    List,
    /// Add a remote rule source
    Add {
        /// Source name
        name: String,
        /// Remote URL
        url: String,
        /// Format: yaml | modsec | json
        #[arg(long, default_value = "yaml")]
        format: String,
    },
    /// Remove a rule source by name
    Remove {
        /// Source name
        name: String,
    },
    /// Fetch latest rules from a source (or all sources)
    Update {
        /// Source name (optional — all sources if omitted)
        name: Option<String>,
    },
    /// Sync all configured sources
    Sync,
}

// ── Bot sub-commands ──────────────────────────────────────────────────────────

/// Bot detection sub-commands
#[derive(Subcommand, Debug)]
enum BotCommands {
    /// List known bot signatures
    List,
    /// Add a bot pattern
    Add {
        /// Regex pattern to match against User-Agent
        pattern: String,
        /// Action: block | log | captcha | allow
        #[arg(long, default_value = "block")]
        action: String,
    },
    /// Remove a bot pattern
    Remove {
        /// Pattern to remove
        pattern: String,
    },
    /// Test a User-Agent string against all bot rules
    Test {
        /// User-Agent string to test
        user_agent: String,
    },
}

// ── GeoIP sub-commands ────────────────────────────────────────────────────────

/// `GeoIP` database sub-commands
#[derive(Subcommand, Debug)]
enum GeoIpCommands {
    /// Download xdb files from upstream (first-time setup or forced refresh)
    Download,
    /// Check for updates and download if newer files are available
    Update,
    /// Show current xdb file info (path, size, modification date)
    Status,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    // Install the process-level rustls CryptoProvider before ANY rustls/QUIC
    // configuration is constructed (cluster mTLS, HTTP/3, outbound TLS). The
    // dependency graph pulls in both `ring` and `aws-lc-rs` transitively, so
    // rustls 0.23 cannot auto-select a provider and would panic at first use
    // (crypto/mod.rs: "Could not automatically determine the process-level
    // CryptoProvider"). Pin `ring` explicitly, exactly once, at startup.
    // `install_default` returns Err only if a provider was already installed;
    // failing here means the process cannot run TLS safely, so bail loudly
    // instead of panicking (Iron Rule #1: no expect in production).
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        anyhow::bail!("failed to install the ring rustls CryptoProvider: a default provider was already set");
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::Directive::from(tracing::Level::INFO)),
        )
        .init();

    let cli = Cli::parse();
    info!("PRX-WAF v{}", env!("CARGO_PKG_VERSION"));

    // Distinguish "no config file" (safe to default) from "config exists but is
    // broken" (must be a hard failure). A parse/validation error is never
    // silently swallowed into a default config (plan §14.1 / P1a must-fix P1-4).
    let mut config = match load_config(&cli.config) {
        Ok(cfg) => cfg,
        Err(ConfigError::NotFound(path)) => {
            tracing::warn!("Config file {path} not found; using built-in defaults.");
            AppConfig::default()
        }
        Err(e @ (ConfigError::Parse(_) | ConfigError::Validate(_))) => {
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    // Overlay environment-variable overrides (DATABASE_URL, PRXWAF_*) so
    // security-critical and deployment-specific settings can be configured in
    // one place without editing per-node TOML. A malformed override is a hard
    // startup error rather than a silent wrong default.
    apply_env_overrides(&mut config)?;

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
            run_server(&config)?;
        }
        Commands::Crowdsec(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_crowdsec_cmd(sub, &config))?;
        }
        Commands::Rules(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_rules_cmd(sub, &config))?;
        }
        Commands::Sources(sub) => {
            run_sources_cmd(sub, &config)?;
        }
        Commands::Bot(sub) => {
            run_bot_cmd(sub, &config)?;
        }
        Commands::Geoip(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_geoip_cmd(sub, &config))?;
        }
        Commands::Community(sub) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_community_cmd(sub, &config))?;
        }
        Commands::Cluster(sub) => {
            run_cluster_cmd(sub, &config)?;
        }
    }

    Ok(())
}

// ── GeoIP commands ────────────────────────────────────────────────────────────

async fn run_geoip_cmd(cmd: GeoIpCommands, config: &AppConfig) -> anyhow::Result<()> {
    use std::path::PathBuf;
    use waf_engine::geoip_updater::xdb_file_info;

    // Derive the data directory from the configured xdb path.
    let data_dir = PathBuf::from(&config.geoip.ipv4_xdb_path)
        .parent()
        .map_or_else(|| PathBuf::from("data"), std::path::Path::to_path_buf);

    let source_url = config.geoip.auto_update.source_url.clone();
    let updater = XdbUpdater::new(data_dir.clone(), source_url);

    match cmd {
        GeoIpCommands::Download => {
            println!("Downloading ip2region xdb files...");
            println!("  Source: {}", config.geoip.auto_update.source_url);
            println!("  Target: {}/", data_dir.display());
            println!();

            match updater.download().await {
                Ok(result) => {
                    if result.ipv4_updated {
                        println!("  IPv4 xdb: {} bytes", result.ipv4_size);
                    }
                    if result.ipv6_updated {
                        println!("  IPv6 xdb: {} bytes", result.ipv6_size);
                    }
                    println!();
                    println!("Download complete.");
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            }
        }

        GeoIpCommands::Update => {
            println!("Checking for ip2region xdb updates...");

            let policy = cache_policy_from_str(&config.geoip.cache_policy);
            let geoip = GeoIpService::init(&config.geoip.ipv4_xdb_path, &config.geoip.ipv6_xdb_path, policy)?;

            match updater.update(&geoip).await {
                Ok(result) if result.ipv4_updated || result.ipv6_updated => {
                    println!("Updated successfully:");
                    if result.ipv4_updated {
                        println!("  IPv4 xdb: {} bytes", result.ipv4_size);
                    }
                    if result.ipv6_updated {
                        println!("  IPv6 xdb: {} bytes", result.ipv6_size);
                    }
                }
                Ok(_) => {
                    println!("Already up to date.");
                }
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            }
        }

        GeoIpCommands::Status => {
            println!("GeoIP xdb Status");
            println!("================");
            println!();

            let v4_path = std::path::Path::new(&config.geoip.ipv4_xdb_path);
            let v6_path = std::path::Path::new(&config.geoip.ipv6_xdb_path);

            println!("  IPv4:  {}", xdb_file_info(v4_path));
            println!("  IPv6:  {}", xdb_file_info(v6_path));
            println!();
            println!("  Config:");
            println!("    Enabled:        {}", config.geoip.enabled);
            println!("    Cache policy:   {}", config.geoip.cache_policy);
            println!("    Auto-update:    {}", config.geoip.auto_update.enabled);
            println!("    Interval:       {}", config.geoip.auto_update.interval);
            println!("    Source URL:     {}", config.geoip.auto_update.source_url);
        }
    }

    Ok(())
}

// ── Rules commands ────────────────────────────────────────────────────────────

#[allow(clippy::significant_drop_tightening)]
async fn run_rules_cmd(cmd: RulesCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        RulesCommands::List { category, source } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let reg = manager.registry.read();
            let rules: Vec<_> = match (&category, &source) {
                (Some(cat), _) => reg.filter_by_category(cat),
                (_, Some(src)) => reg.filter_by_source(src),
                _ => reg.list(),
            };

            println!(
                "{:<20} {:<35} {:<12} {:<16} {:<8} Action",
                "ID", "Name", "Category", "Source", "Status"
            );
            println!("{}", "-".repeat(100));
            for rule in &rules {
                println!(
                    "{:<20} {:<35} {:<12} {:<16} {:<8} {}",
                    truncate(&rule.id, 19),
                    truncate(&rule.name, 34),
                    truncate(&rule.category, 11),
                    truncate(&rule.source, 15),
                    if rule.enabled { "enabled" } else { "disabled" },
                    rule.action,
                );
            }
            println!("\nTotal: {} rules", rules.len());
        }

        RulesCommands::Info { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let reg = manager.registry.read();
            match reg.get(&rule_id) {
                Some(rule) => {
                    println!("ID:          {}", rule.id);
                    println!("Name:        {}", rule.name);
                    println!("Category:    {}", rule.category);
                    println!("Source:      {}", rule.source);
                    println!("Status:      {}", if rule.enabled { "enabled" } else { "disabled" });
                    println!("Action:      {}", rule.action);
                    if let Some(sev) = &rule.severity {
                        println!("Severity:    {sev}");
                    }
                    if let Some(desc) = &rule.description {
                        println!("Description: {desc}");
                    }
                    if let Some(pattern) = &rule.pattern {
                        println!("Pattern:     {pattern}");
                    }
                    if !rule.tags.is_empty() {
                        println!("Tags:        {}", rule.tags.join(", "));
                    }
                }
                None => println!("Rule not found: {rule_id}"),
            }
        }

        RulesCommands::Enable { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            manager.enable_rule(&rule_id)?;
            println!("Rule enabled: {rule_id}");
        }

        RulesCommands::Disable { rule_id } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            manager.disable_rule(&rule_id)?;
            println!("Rule disabled: {rule_id}");
        }

        RulesCommands::Reload => {
            let mut manager = RuleManager::new(&config.rules);
            let report = manager.reload()?;
            println!("{report}");
        }

        RulesCommands::Validate { path } => {
            let manager = RuleManager::new(&config.rules);
            let errors = manager.validate_file(&path)?;
            if errors.is_empty() {
                println!("OK: {} is valid", path.display());
            } else {
                println!("{} validation errors in {}:", errors.len(), path.display());
                for err in &errors {
                    println!("  - {err}");
                }
                std::process::exit(1);
            }
        }

        RulesCommands::Import { source } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let count = if source.starts_with("http://") || source.starts_with("https://") {
                manager.import_from_url(&source).await?
            } else {
                manager.import_from_file(std::path::Path::new(&source))?
            };
            println!("Imported {count} rules from {source}");
        }

        RulesCommands::Export { format } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let fmt = ExportFormat::parse_str(&format);
            let output = manager.export(fmt)?;
            print!("{output}");
        }

        RulesCommands::Update => {
            println!("Fetching remote rule sources...");
            let mut manager = RuleManager::new(&config.rules);
            let results = manager.load_remote_sources().await;
            if results.is_empty() {
                println!("No remote rule sources configured.");
            } else {
                let mut had_error = false;
                for (name, result) in &results {
                    match result {
                        Ok(n) => println!("  {name}: {n} rules loaded"),
                        Err(e) => {
                            eprintln!("  {name}: ERROR: {e}");
                            had_error = true;
                        }
                    }
                }
                if had_error {
                    anyhow::bail!("One or more remote sources failed to load");
                }
                println!("Done.");
            }
        }

        RulesCommands::Search { query } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;

            let results = manager.search(&query);
            if results.is_empty() {
                println!("No rules matched '{query}'");
            } else {
                println!("{} result(s) for '{query}':", results.len());
                for rule in &results {
                    println!("  {} — {} [{}]", rule.id, rule.name, rule.category);
                }
            }
        }

        RulesCommands::Stats => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let stats = manager.stats();

            println!("Rule Statistics");
            println!("===============");
            println!("  Total:    {}", stats.total);
            println!("  Enabled:  {}", stats.enabled);
            println!("  Disabled: {}", stats.disabled);
            println!("  Version:  {}", stats.version);
            println!();
            println!("By Category:");
            let mut cats: Vec<_> = stats.by_category.iter().collect();
            cats.sort_by_key(|(k, _)| k.as_str());
            for (cat, count) in cats {
                println!("  {cat:<20} {count}");
            }
            println!();
            println!("By Source:");
            let mut srcs: Vec<_> = stats.by_source.iter().collect();
            srcs.sort_by_key(|(k, _)| k.as_str());
            for (src, count) in srcs {
                println!("  {src:<20} {count}");
            }
        }
    }

    Ok(())
}

// ── Sources commands ──────────────────────────────────────────────────────────

#[allow(clippy::unnecessary_wraps)]
fn run_sources_cmd(cmd: SourcesCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        SourcesCommands::List => {
            println!("{:<20} {:<12} URL/Path", "Name", "Type");
            println!("{}", "-".repeat(80));
            for src in &config.rules.sources {
                let type_str = if src.url.is_some() { "remote_url" } else { "local" };
                let location = src.url.as_deref().or(src.path.as_deref()).unwrap_or("-");
                println!("{:<20} {:<12} {}", src.name, type_str, location);
            }
            if config.rules.enable_builtin_owasp {
                println!("{:<20} {:<12} (compiled-in)", "builtin-owasp", "builtin");
            }
            if config.rules.enable_builtin_bot {
                println!("{:<20} {:<12} (compiled-in)", "builtin-bot", "builtin");
            }
            if config.rules.enable_builtin_scanner {
                println!("{:<20} {:<12} (compiled-in)", "builtin-scanner", "builtin");
            }
        }
        SourcesCommands::Add { name, url, format } => {
            println!("Add source '{name}' ({format}): {url}");
            println!("Note: add the following to your [rules.sources] config:");
            println!();
            println!("[[rules.sources]]");
            println!("name   = \"{name}\"");
            println!("url    = \"{url}\"");
            println!("format = \"{format}\"");
        }
        SourcesCommands::Remove { name } => {
            println!("Remove source '{name}': edit configs/default.toml and remove the [[rules.sources]] entry.");
        }
        SourcesCommands::Update { name } => {
            if let Some(name) = name {
                println!("Updating source '{name}'... (run `prx-waf rules update` to fetch)");
            } else {
                println!("Updating all sources... (run `prx-waf rules update` to fetch all)");
            }
        }
        SourcesCommands::Sync => {
            println!("Syncing all sources... run `prx-waf rules update` to fetch.");
        }
    }
    Ok(())
}

// ── Bot commands ──────────────────────────────────────────────────────────────

#[allow(clippy::significant_drop_tightening)]
fn run_bot_cmd(cmd: BotCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        BotCommands::List => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let reg = manager.registry.read();
            let bot_rules = reg.filter_by_category("bot");

            println!("{:<20} {:<40} {:<8} Tags", "ID", "Name", "Action");
            println!("{}", "-".repeat(100));
            for rule in bot_rules {
                println!(
                    "{:<20} {:<40} {:<8} {}",
                    truncate(&rule.id, 19),
                    truncate(&rule.name, 39),
                    rule.action,
                    rule.tags.join(", "),
                );
            }
        }

        BotCommands::Add { pattern, action } => {
            println!("Bot pattern added: {pattern} → {action}");
            println!("Note: persistent storage requires database integration.");
            println!("To make permanent, add a YAML rule to your rules/ directory:");
            println!();
            println!("- id: \"BOT-CUSTOM-001\"");
            println!("  name: \"Custom bot pattern\"");
            println!("  category: \"bot\"");
            println!("  action: \"{action}\"");
            println!("  pattern: \"{pattern}\"");
        }

        BotCommands::Remove { pattern } => {
            println!("Remove bot pattern: {pattern}");
            println!("Note: remove the corresponding rule from your rules/ directory.");
        }

        BotCommands::Test { user_agent } => {
            let mut manager = RuleManager::new(&config.rules);
            manager.load_all()?;
            let reg = manager.registry.read();
            let bot_rules = reg.filter_by_category("bot");

            let mut matched = false;
            for rule in bot_rules {
                if let Some(pattern) = &rule.pattern
                    && let Ok(re) = regex::Regex::new(pattern.as_str())
                    && re.is_match(user_agent.as_str())
                {
                    println!("MATCH: {} — {} (action: {})", rule.id, rule.name, rule.action);
                    matched = true;
                }
            }
            if !matched {
                println!("No bot rules matched: {user_agent}");
            }
        }
    }
    Ok(())
}

// ── Cluster commands ──────────────────────────────────────────────────────────

fn run_cluster_cmd(cmd: ClusterCommands, config: &AppConfig) -> anyhow::Result<()> {
    let cluster_addr = config
        .cluster
        .as_ref()
        .map_or("(not configured)", |c| c.listen_addr.as_str());

    match cmd {
        ClusterCommands::Status => {
            println!("Cluster Status");
            println!("==============");
            println!();
            if let Some(cluster) = &config.cluster {
                println!("  Enabled:    {}", cluster.enabled);
                println!("  Listen:     {}", cluster.listen_addr);
                println!("  Role:       {}", cluster.role);
                println!("  Node ID:    {}", cluster.node_id);
                println!("  Seeds:      {}", cluster.seeds.join(", "));
            } else {
                println!("  [INFO] Cluster is not configured. Add a [cluster] section to your config.");
            }
        }

        ClusterCommands::Nodes => {
            println!("Cluster Nodes");
            println!("=============");
            println!();
            if let Some(cluster) = &config.cluster {
                println!("  This node:  {} ({})", cluster.node_id, cluster.listen_addr);
                if cluster.seeds.is_empty() {
                    println!("  Peers:      (none configured)");
                } else {
                    println!("  Configured seeds:");
                    for seed in &cluster.seeds {
                        println!("    - {seed}");
                    }
                }
                println!();
                println!("  Note: live node list is only available through the running cluster API.");
            } else {
                println!("  [INFO] Cluster is not configured.");
            }
        }

        ClusterCommands::Token(ClusterTokenCommands::Generate { ttl }) => {
            println!("Cluster Join Token");
            println!("==================");
            println!();
            println!("  Listen addr: {cluster_addr}");
            println!("  TTL:         {ttl}");
            println!();
            println!("  Note: token generation requires a running cluster node.");
            println!("  Use the management API to generate tokens:");
            println!("    POST /api/v1/cluster/tokens  {{ \"ttl\": \"{ttl}\" }}");
        }

        ClusterCommands::Promote { node_id } => {
            println!("Promote node '{node_id}' to Main");
            println!("Note: use the management API: POST /api/v1/cluster/nodes/{node_id}/promote");
        }

        ClusterCommands::Demote { node_id } => {
            println!("Demote node '{node_id}' to Worker");
            println!("Note: use the management API: POST /api/v1/cluster/nodes/{node_id}/demote");
        }

        ClusterCommands::Remove { node_id } => {
            println!("Remove node '{node_id}' from cluster");
            println!("Note: use the management API: DELETE /api/v1/cluster/nodes/{node_id}");
        }

        ClusterCommands::CertInit {
            nodes,
            output_dir,
            ca_validity_days,
            node_validity_days,
        } => {
            run_cert_init(&nodes, &output_dir, ca_validity_days, node_validity_days)?;
        }
    }

    Ok(())
}

/// Generate cluster CA and per-node certificates and write them to `output_dir`.
fn run_cert_init(nodes: &str, output_dir: &str, ca_validity_days: u32, node_validity_days: u32) -> anyhow::Result<()> {
    use std::fs;
    use std::path::Path;

    use waf_cluster::crypto::ca::CertificateAuthority;
    use waf_cluster::crypto::node_cert::NodeCertificate;

    let output = Path::new(output_dir);
    fs::create_dir_all(output).map_err(|e| anyhow::anyhow!("failed to create output directory '{output_dir}': {e}"))?;

    // Generate cluster CA.
    let ca = CertificateAuthority::generate(ca_validity_days)
        .map_err(|e| anyhow::anyhow!("failed to generate cluster CA: {e}"))?;

    let ca_cert_path = output.join("cluster-ca.pem");
    let ca_key_path = output.join("cluster-ca.key");
    fs::write(&ca_cert_path, ca.cert_pem())
        .map_err(|e| anyhow::anyhow!("failed to write CA cert to '{}': {e}", ca_cert_path.display()))?;
    fs::write(&ca_key_path, ca.key_pem())
        .map_err(|e| anyhow::anyhow!("failed to write CA key to '{}': {e}", ca_key_path.display()))?;

    println!("Generated cluster CA:");
    println!("  Cert: {}", ca_cert_path.display());
    println!("  Key:  {} (keep this secret)", ca_key_path.display());
    println!();

    // Generate per-node certificates.
    let node_names: Vec<&str> = nodes.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if node_names.is_empty() {
        anyhow::bail!("--nodes must contain at least one node name");
    }

    for node_name in &node_names {
        let node_cert = NodeCertificate::generate(node_name, &ca, node_validity_days)
            .map_err(|e| anyhow::anyhow!("failed to generate certificate for node '{node_name}': {e}"))?;

        let cert_path = output.join(format!("{node_name}.pem"));
        let key_path = output.join(format!("{node_name}.key"));
        fs::write(&cert_path, &node_cert.cert_pem)
            .map_err(|e| anyhow::anyhow!("failed to write cert for '{node_name}': {e}"))?;
        fs::write(&key_path, &node_cert.key_pem)
            .map_err(|e| anyhow::anyhow!("failed to write key for '{node_name}': {e}"))?;

        println!("  Node '{node_name}':");
        println!("    Cert: {}", cert_path.display());
        println!("    Key:  {}", key_path.display());
    }

    println!();
    println!("Certificates generated for nodes: {}", node_names.join(", "));
    println!("Distribute 'cluster-ca.pem' to all nodes (read-only mount).");
    println!("Each node loads its own cert/key pair from the output directory.");
    println!("The CA key 'cluster-ca.key' is only needed on the main node.");

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

// ── Community commands ────────────────────────────────────────────────────────

async fn run_community_cmd(cmd: CommunityCommands, config: &AppConfig) -> anyhow::Result<()> {
    match cmd {
        CommunityCommands::Status => {
            println!("Community Threat Intelligence Status");
            println!("====================================");
            println!("  Enabled:    {}", config.community.enabled);
            println!("  Server URL: {}", config.community.server_url);
            println!(
                "  Machine ID: {}",
                config.community.machine_id.as_deref().unwrap_or("(not enrolled)")
            );
            println!(
                "  API Key:    {}",
                if config.community.api_key.is_some() {
                    "(configured)"
                } else {
                    "(not set)"
                }
            );
            println!("  Batch size: {}", config.community.batch_size);
            println!("  Flush interval: {}s", config.community.flush_interval_secs);
            println!("  Sync interval:  {}s", config.community.sync_interval_secs);
            if !config.community.enabled {
                println!();
                println!("  [INFO] Community sharing is disabled. Enable it in configs/default.toml.");
            }
        }

        CommunityCommands::Enroll => {
            println!(
                "Enrolling machine with community server: {}",
                config.community.server_url
            );
            let client = waf_engine::CommunityClient::new(&config.community.server_url)?;
            match waf_engine::community::enroll::enroll_machine(&client).await {
                Ok(resp) => {
                    println!();
                    println!("Enrollment successful!");
                    println!("  Machine ID: {}", resp.machine_id);
                    println!("  API Key:    {}", resp.api_key);
                    if let Some(cred) = resp.enrollment_credential {
                        println!("  Credential: {cred}");
                    }
                    println!();
                    println!("Add to your configs/default.toml:");
                    println!();
                    println!("[community]");
                    println!("enabled = true");
                    println!("server_url = \"{}\"", config.community.server_url);
                    println!("machine_id = \"{}\"", resp.machine_id);
                    println!("api_key = \"{}\"", resp.api_key);
                }
                Err(e) => {
                    eprintln!("Enrollment failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        CommunityCommands::Test => {
            println!("Testing connection to: {}", config.community.server_url);
            let client = waf_engine::CommunityClient::new(&config.community.server_url)?;
            let api_key_ref = config.community.api_key.as_deref();
            match client.test_connection(api_key_ref).await {
                Ok(msg) => println!("OK: {msg}"),
                Err(e) => println!("FAILED: {e}"),
            }
        }
    }

    Ok(())
}

// ── Existing implementations (unchanged) ─────────────────────────────────────

async fn run_migrate(config: &AppConfig) -> anyhow::Result<()> {
    info!("Running database migrations...");
    let db = Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    db.migrate().await?;
    info!("Migrations complete.");
    Ok(())
}

async fn run_seed_admin(config: &AppConfig) -> anyhow::Result<()> {
    info!("Connecting to database...");
    let db = Arc::new(Database::connect(&config.storage.database_url, config.storage.max_connections).await?);
    db.migrate().await?;

    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let state = Arc::new(AppState::new(Arc::clone(&db), engine, router)?);

    waf_api::auth::ensure_default_admin(&state).await?;
    info!("Default admin user seeded (username=admin, password=admin). Change it immediately!");
    Ok(())
}

/// Handle `CrowdSec` CLI sub-commands
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
            let client = CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            let stream = client.get_decisions_stream(true).await?;
            let decisions = stream.new.unwrap_or_default();
            println!("Active decisions ({}):", decisions.len());
            println!(
                "{:<18} {:<12} {:<40} {:<12} Duration",
                "Value", "Type", "Scenario", "Origin"
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
            let client = CrowdSecClient::new(cs_config.lapi_url.clone(), cs_config.api_key.clone())?;
            match client.test_connection().await {
                Ok(msg) => println!("OK: {msg}"),
                Err(e) => println!("FAILED: {e}"),
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

/// Convert the flat `AppConfig` `CrowdSecConfig` to the engine's `CrowdSecConfig` type.
fn app_config_to_crowdsec(config: &AppConfig) -> CrowdSecConfig {
    use waf_engine::crowdsec::config::{AppSecConfig, CrowdSecMode, FallbackAction, PusherConfig};

    let mode = match config.crowdsec.mode.as_str() {
        "appsec" => CrowdSecMode::Appsec,
        "both" => CrowdSecMode::Both,
        _ => CrowdSecMode::Bouncer,
    };

    let parse_fallback = |value: &str| match value {
        "block" => FallbackAction::Block,
        "log" => FallbackAction::Log,
        _ => FallbackAction::Allow,
    };

    let fallback = parse_fallback(config.crowdsec.fallback_action.as_str());

    let appsec = config.crowdsec.appsec_endpoint.as_ref().map(|endpoint| AppSecConfig {
        endpoint: endpoint.clone(),
        api_key: config.crowdsec.appsec_key.clone().unwrap_or_default(),
        timeout_ms: config.crowdsec.appsec_timeout_ms,
        // H-4: AppSec has its own dedicated failure_action, configured
        // independently of the LAPI bouncer's fallback_action. Defaults to
        // Allow (fail open) for backward compatibility.
        failure_action: parse_fallback(config.crowdsec.appsec_failure_action.as_str()),
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

    // Category ③ (external dependency): CrowdSec stays off for a zero-config
    // single node — it needs an external LAPI endpoint + bouncer key. Rather
    // than hard-enabling it (which would be a no-op or error without a LAPI),
    // treat "an api_key is configured" as intent to enable, so operators only
    // set the key. With no key the default remains disabled. This derivation is
    // the single source of truth shared by the runtime and the `crowdsec`
    // CLI, so both agree. A failed init still fails safe (logged, non-fatal).
    let enabled = config.crowdsec.enabled || !config.crowdsec.api_key.trim().is_empty();

    CrowdSecConfig {
        enabled,
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
fn run_server(config: &AppConfig) -> anyhow::Result<()> {
    use pingora_core::server::Server;

    // Report the admin-API reachable surface before anything else binds, so
    // the very first thing an operator sees is whether the management API is
    // exposed and what to do about it.
    for line in admin_exposure_startup_broadcast(&config.api, &config.security) {
        match line.level {
            BroadcastLevel::Info => info!("{}", line.text),
            BroadcastLevel::Warn => tracing::warn!("{}", line.text),
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    // `_shutdown_guards` holds the watch senders that signal background workers
    // to stop.  They are dropped automatically when `run_server` returns (after
    // `server.run_forever()` exits), which sends the shutdown signal.
    let (engine, router, api_state, acme_challenges, lb_registry, response_cache, _shutdown_guards, cluster_node_state) =
        rt.block_on(init_async(config))?;

    // Start the management API in a background thread
    let api_listen = config.api.listen_addr.clone();
    let api_state_bg = Arc::clone(&api_state);
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("Failed to build API runtime: {e}");
                return;
            }
        };
        rt.block_on(async move {
            if let Err(e) = start_api_server(&api_listen, api_state_bg).await {
                tracing::error!("API server error: {}", e);
            }
        });
    });

    // Category ③ (external dependency): HTTP/3 needs a TLS cert + key, so it is
    // off for a zero-config single node. Rather than hard-enabling it (which
    // would fail without certificates), treat "both cert_pem and key_pem are
    // configured" as intent to enable — an operator who points HTTP/3 at a
    // keypair clearly wants it. With no certs it stays disabled.
    let http3_enabled = config.http3.enabled || (config.http3.cert_pem.is_some() && config.http3.key_pem.is_some());

    // Optionally start HTTP/3 listener
    if http3_enabled {
        let h3_config = config.http3.clone();
        let h3_smuggling_detection = config.proxy.smuggling_detection;
        let h3_engine = Arc::clone(&engine);
        let h3_router = Arc::clone(&router);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build HTTP/3 runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let cert_pem = if let Some(p) = h3_config.cert_pem.as_deref() {
                    match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("HTTP/3 cert read error: {e}");
                            return;
                        }
                    }
                } else {
                    tracing::error!("HTTP/3 cert_pem not configured");
                    return;
                };
                let key_pem = if let Some(p) = h3_config.key_pem.as_deref() {
                    match std::fs::read_to_string(p) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("HTTP/3 key read error: {e}");
                            return;
                        }
                    }
                } else {
                    tracing::error!("HTTP/3 key_pem not configured");
                    return;
                };
                let addr: std::net::SocketAddr = match h3_config.listen_addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("HTTP/3 listen_addr parse error: {e}");
                        return;
                    }
                };
                // Upstream is selected per-host via the router inside the H3
                // server (same source as Pingora's upstream_peer); no hard-coded
                // backend here (audit H-7).
                if let Err(e) = gateway::http3::start_http3_server(
                    addr,
                    cert_pem,
                    key_pem,
                    h3_config.upstream_tls_verify,
                    h3_smuggling_detection,
                    Arc::clone(&h3_engine),
                    Arc::clone(&h3_router),
                )
                .await
                {
                    tracing::error!("HTTP/3 server error: {e}");
                }
            });
        });
    }

    // Optionally start cluster node
    if let Some(cluster_cfg) = config.cluster.clone()
        && cluster_cfg.enabled
    {
        // Cluster↔engine wiring: applied rule syncs notify the running WafEngine
        // (which implements RuleReloader) so the data plane refreshes.
        let engine_reloader = Arc::clone(&engine);
        let cluster_reloader: Arc<dyn waf_cluster::RuleReloader> = engine_reloader;
        // Run on the SAME node state shared with the API layer + engine (built in
        // init_async), so both rule-sync hooks operate on one instance.
        let shared_node_state = cluster_node_state;
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build cluster runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                match waf_cluster::ClusterNode::new(cluster_cfg) {
                    Ok(node) => {
                        let mut node = node.with_rule_reloader(cluster_reloader);
                        if let Some(state) = shared_node_state {
                            node = node.with_node_state(state);
                        }
                        if let Err(e) = node.run().await {
                            tracing::error!("Cluster node error: {e}");
                        }
                    }
                    Err(e) => tracing::error!("Failed to create cluster node: {e}"),
                }
            });
        });
    }

    // Build and run Pingora proxy (blocks forever)
    let mut server = Server::new(None)?;
    server.bootstrap();

    // ── Response-phase detectors ──────────────────────────────────────────────
    // The CRS check is registered here, and only when it actually has
    // response-phase rules loaded. That condition is the whole contract of the
    // response path: `ResponseCheckSet::is_empty()` gates every response-phase
    // action in the gateway, so a deployment whose rule directory carries no
    // `RESPONSE-95x` file keeps the exact response path it had before response
    // inspection existed — nothing gated, nothing folded, nothing buffered.
    let response_checks = {
        let owasp = Arc::clone(engine.owasp_check());
        let count = owasp.response_rule_count();
        if count == 0 {
            info!("Response-phase WAF: no CRS response rules loaded — response inspection stays off");
            ResponseCheckSet::new()
        } else {
            let policy = gateway::response_inspection_policy();
            info!(
                "Response-phase WAF: {count} CRS response rule(s) armed in {:?} mode \
                 (PRXWAF_RESPONSE_INSPECT_MODE), inspecting up to {} body bytes per response",
                policy.mode, policy.max_total_bytes,
            );
            ResponseCheckSet::from_checks(vec![Box::new(owasp)])
        }
    };

    let mut proxy = WafProxy::new(router, engine);
    proxy.response_checks = Arc::new(response_checks);
    proxy.acme_challenges = acme_challenges;
    proxy.lb_registry = lb_registry;
    proxy.cache = response_cache;
    proxy.trust_proxy_headers = config.proxy.trust_proxy_headers;
    proxy.smuggling_detection = config.proxy.smuggling_detection;
    proxy.trusted_proxies = config
        .proxy
        .trusted_proxies
        .iter()
        .filter_map(|s| match s.parse::<ipnet::IpNet>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!("Ignoring invalid trusted_proxies entry '{}': {}", s, e);
                None
            }
        })
        .collect();

    // Refuse to start when XFF trust is enabled but no trusted proxy CIDRs are
    // configured (M-1). Honouring X-Forwarded-For from ANY source lets clients
    // spoof their IP to bypass IP blocklists and rate limits, so this fail-open
    // misconfiguration is now a hard startup error rather than a warning.
    if proxy.trust_proxy_headers && proxy.trusted_proxies.is_empty() {
        anyhow::bail!(
            "invalid proxy configuration: [proxy].trust_proxy_headers is enabled but \
             [proxy].trusted_proxies is empty. This would trust X-Forwarded-For headers from \
             ANY source, allowing clients to spoof their IP and bypass IP blocklists / rate \
             limits. Configure trusted_proxies with the CIDR ranges of your reverse proxies, \
             or set trust_proxy_headers = false."
        );
    }

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.proxy.listen_addr);
    server.add_service(proxy_service);

    info!("Proxy listening on {}", config.proxy.listen_addr);
    info!("Management API listening on {}", config.api.listen_addr);
    if http3_enabled {
        info!("HTTP/3 (QUIC) listener on {}", config.http3.listen_addr);
    }
    info!("Press Ctrl+C to stop");

    server.run_forever();
}

/// Severity a [`BroadcastLine`] must be logged at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BroadcastLevel {
    Info,
    Warn,
}

/// One line of the Lane 2 enforcement startup broadcast.
#[derive(Debug, Clone)]
struct BroadcastLine {
    level: BroadcastLevel,
    text: String,
}

impl BroadcastLine {
    fn info(text: impl Into<String>) -> Self {
        Self {
            level: BroadcastLevel::Info,
            text: text.into(),
        }
    }

    fn warn(text: impl Into<String>) -> Self {
        Self {
            level: BroadcastLevel::Warn,
            text: text.into(),
        }
    }
}

/// Render a family list for the broadcast: `a, b, c`, or `none` when empty.
fn render_family_list(items: &[&str]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

/// Build the Lane 2 semantic content-security startup broadcast.
///
/// This is the operator-facing answer to the only question that matters at boot:
/// **will this process return a 403 from the semantic lane, or not?** It reports
/// the real conditions the request path applies in
/// `ContentSecuritySubsystem::resolve_enforced_action`, all of which must hold
/// for a semantic verdict to become a Block:
///
/// 1. the lane is enabled and the global `enforcement_mode` is not `off`
///    (a global `off` short-circuits the lane before detection, so per-family
///    overrides are inert);
/// 2. the verdict's primary family resolves to `enforce` — either from the
///    global mode or from an `enforcement_overrides` entry — and that family is
///    enabled in `[content_security.attacks.*]`;
/// 3. `rollout_bps > 0` and the request's client-IP canary bucket falls inside
///    it (`rollout_bps = 0` therefore closes the gate for every request);
/// 4. the restart warmup latch has lifted — enforcement is held to shadow for
///    `breaker.window` after process start;
/// 5. the anomaly-rate circuit breaker is not open;
/// 6. the host is not in `log_only_mode`;
/// 7. the verdict is `enforce_safe` — a Block carried solely by blind/synthetic
///    views (base64/hex/comment-strip/HPP/parse-error) is held to shadow.
///
/// Conditions 5–7 are per-request/per-host and cannot be decided at startup, so
/// they are stated as caveats on the "WILL BLOCK" verdict. Conditions 1–4 are
/// static configuration and are decided here.
///
/// `rt` is the compiled config the engine actually runs on; `cfg` supplies the
/// stably ordered, string-keyed family and override maps (the compiled runtime
/// form uses unordered `HashMap`s keyed by a non-exported enum).
fn content_security_startup_broadcast(
    rt: &RuntimeContentSecurityConfig,
    cfg: &waf_common::content_security_config::ContentSecurityConfig,
) -> Vec<BroadcastLine> {
    if !rt.enabled {
        return vec![BroadcastLine::info(
            "Lane 2 semantic content-security engine DISABLED (content_security.enabled=false): no semantic detection, no shadow logging, no observation rows. WILL NOT BLOCK. Lane 1 legacy checkers are unaffected.",
        )];
    }

    let global = match rt.enforcement_mode {
        EnforcementMode::Off => "off",
        EnforcementMode::LogOnly => "log_only",
        EnforcementMode::Enforce => "enforce",
    };
    let rendered_overrides = if cfg.enforcement_overrides.is_empty() {
        "none".to_string()
    } else {
        cfg.enforcement_overrides
            .iter()
            .map(|(family, mode)| format!("{family}={mode}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    if rt.enforcement_mode == EnforcementMode::Off {
        return vec![BroadcastLine::info(format!(
            "Lane 2 semantic content-security engine enabled but enforcement_mode=off — the lane does NO work (no preprocessing, no detection, no shadow log, no observation row) and per-family overrides are inert (overrides: {rendered_overrides}). WILL NOT BLOCK."
        ))];
    }

    // Effective per-family mode: an `enforcement_overrides` entry wins over the
    // global mode. A family disabled in `[content_security.attacks.*]` is never
    // scored, so it can never block whatever its mode says.
    let mut enforcing: Vec<&str> = Vec::new();
    let mut shadow: Vec<&str> = Vec::new();
    let mut no_action: Vec<&str> = Vec::new();
    let mut disabled: Vec<&str> = Vec::new();
    for (family, attack) in &cfg.attacks {
        if !attack.enabled {
            disabled.push(family.as_str());
            continue;
        }
        match cfg.enforcement_overrides.get(family).map_or(global, String::as_str) {
            "enforce" => enforcing.push(family.as_str()),
            "off" => no_action.push(family.as_str()),
            _ => shadow.push(family.as_str()),
        }
    }

    let warmup_secs = rt.breaker.window.as_secs();
    let rollout_pct = f64::from(rt.rollout_bps) / 100.0;

    let mut lines = vec![
        BroadcastLine::info(format!(
            "Lane 2 semantic content-security engine ACTIVE: global enforcement_mode={global}, per-family enforcement_overrides: {rendered_overrides}"
        )),
        BroadcastLine::info(format!(
            "Lane 2 families — enforce (a match may return 403): {}; log_only (detect + log + persist, never block): {}",
            render_family_list(&enforcing),
            render_family_list(&shadow)
        )),
    ];
    if !no_action.is_empty() || !disabled.is_empty() {
        lines.push(BroadcastLine::info(format!(
            "Lane 2 families — off (still detected + persisted as an observation, but no security event and no block): {}; disabled in [content_security.attacks.*] (never scored at all): {}",
            render_family_list(&no_action),
            render_family_list(&disabled)
        )));
    }
    lines.push(BroadcastLine::info(format!(
        "Lane 2 block gates: rollout_bps={}/10000 (~{rollout_pct:.2}% of client IPs, canary bucketed by client IP), restart warmup latch={warmup_secs}s from process start, breaker window={warmup_secs}s min_samples={} anomaly_rate_threshold={} cooldown={}s",
        rt.rollout_bps,
        rt.breaker.min_samples,
        rt.breaker.anomaly_rate_threshold,
        rt.breaker.cooldown.as_secs()
    )));

    if enforcing.is_empty() {
        lines.push(BroadcastLine::info(
            "Lane 2 VERDICT: WILL NOT BLOCK — no enabled attack family resolves to enforce. Every Lane 2 detection becomes a LogOnly security event plus a semantic_observations row.",
        ));
        return lines;
    }
    let enforcing_list = render_family_list(&enforcing);
    if rt.rollout_bps == 0 {
        lines.push(BroadcastLine::warn(format!(
            "Lane 2 VERDICT: WILL NOT BLOCK — families [{enforcing_list}] are configured to enforce, but rollout_bps=0 closes the canary gate for every request, so every would-be Block is downgraded to a shadow LogOnly. Raise content_security.rollout_bps above 0 to make enforcement take effect."
        )));
        return lines;
    }
    lines.push(BroadcastLine::warn(format!(
        "Lane 2 VERDICT: WILL BLOCK once warmed up — {warmup_secs}s after process start, a request matching [{enforcing_list}] from a client IP inside the ~{rollout_pct:.2}% canary can be answered with a 403. Before the warmup latch lifts, while the circuit breaker is open, for hosts with log_only_mode=true, and for verdicts that are not enforce_safe (carried solely by blind/synthetic base64/hex/comment-strip/HPP/parse-error views), the Block is still downgraded to a shadow LogOnly."
    )));
    lines
}

/// Bind scope of the management API's `[api] listen_addr`, classified from
/// the configured socket address alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminBindScope {
    /// `127.0.0.0/8` or `::1` — reachable only from processes on this host
    /// (this container, if containerized).
    Loopback,
    /// A single non-wildcard, non-loopback address — reachable from whatever
    /// network that one interface sits on.
    Interface,
    /// `0.0.0.0` — reachable on every IPv4 interface of this host/container.
    WildcardV4,
    /// `::` — reachable on every interface of this host/container (IPv4 and
    /// IPv6 alike on most kernels, which default to a dual-stack wildcard).
    WildcardV6,
}

/// Classify `[api] listen_addr`. Returns `None` when it does not parse as
/// `host:port` — the process will fail to bind on that value later; this
/// broadcast just cannot assess a scope for it ahead of time.
fn classify_admin_bind_scope(listen_addr: &str) -> Option<AdminBindScope> {
    let ip = listen_addr.parse::<std::net::SocketAddr>().ok()?.ip();
    Some(if ip.is_loopback() {
        AdminBindScope::Loopback
    } else if ip.is_unspecified() {
        if ip.is_ipv4() {
            AdminBindScope::WildcardV4
        } else {
            AdminBindScope::WildcardV6
        }
    } else {
        AdminBindScope::Interface
    })
}

/// Render `[security] admin_ip_allowlist` for the broadcast.
fn render_admin_allowlist(allowlist: &[String]) -> String {
    if allowlist.is_empty() {
        "empty".to_string()
    } else {
        format!(
            "{} entr{} ({})",
            allowlist.len(),
            if allowlist.len() == 1 { "y" } else { "ies" },
            allowlist.join(", ")
        )
    }
}

/// Build the admin-management-API exposure startup broadcast.
///
/// Answers the operator's other boot-time question, alongside Lane 2's "will
/// this block?": **who can reach the management API, and what can they do if
/// they get there?** The management API can rewrite WAF rules, upload WASM
/// plugins, mint cluster-join tokens, and replace TLS certificates; its only
/// gate is a JWT bootstrapped from a password printed once at first startup,
/// plus whatever `[security] admin_ip_allowlist` restricts. This combines
/// that with the actual bind scope of `[api] listen_addr` — the two settings
/// that jointly decide the real reachable surface. It cannot see a Docker
/// host port publish or an external firewall, so it says so whenever the bind
/// is wider than loopback.
fn admin_exposure_startup_broadcast(api: &ApiConfig, security: &SecurityConfig) -> Vec<BroadcastLine> {
    let allowlist_desc = render_admin_allowlist(&security.admin_ip_allowlist);
    let addr = &api.listen_addr;

    let Some(scope) = classify_admin_bind_scope(addr) else {
        return vec![BroadcastLine::warn(format!(
            "Admin API exposure UNKNOWN: [api] listen_addr={addr:?} does not parse as host:port, so its bind scope cannot be assessed here. The server will fail to bind on startup if this value is invalid; if it is valid but unusual, verify manually that it does not expose the management API wider than intended (admin_ip_allowlist: {allowlist_desc})."
        ))];
    };

    match scope {
        AdminBindScope::Loopback if security.admin_ip_allowlist.is_empty() => vec![BroadcastLine::info(format!(
            "Admin API bind: {addr} is loopback-only — reachable only from processes on this host (this container, if containerized). [security] admin_ip_allowlist is empty, but that adds no exposure here since the bind itself already blocks every off-host source. If this runs under Docker, the host-side port publish in docker-compose.yml decides what's reachable from outside the container (\"127.0.0.1:16827:9527\" keeps it host-local; publishing it as \"0.0.0.0:...\" or unqualified \"16827:9527\" would re-expose it network-wide even though this bind stays loopback)."
        ))],
        AdminBindScope::Loopback => vec![BroadcastLine::info(format!(
            "Admin API bind: {addr} is loopback-only, and [security] admin_ip_allowlist additionally restricts to {allowlist_desc}. The allowlist is redundant given the loopback bind (harmless) — it only matters if something reaches this port over a non-loopback path, e.g. a Docker port publish wider than 127.0.0.1."
        ))],
        AdminBindScope::Interface if security.admin_ip_allowlist.is_empty() => vec![BroadcastLine::warn(format!(
            "Admin API exposure: [api] listen_addr={addr} binds to a specific non-loopback interface, and [security] admin_ip_allowlist is empty — every host that can route to that interface's network can reach the management API (WAF rule edits, WASM plugin upload, cluster-join tokens, TLS certificate changes), gated only by the JWT login (bootstrapped from the once-printed admin password). Fix by setting [security] admin_ip_allowlist to the trusted admin IP(s)/CIDR(s), or bind [api] listen_addr to 127.0.0.1 and put a tunnel/reverse proxy in front for remote access."
        ))],
        AdminBindScope::Interface => vec![BroadcastLine::info(format!(
            "Admin API exposure: [api] listen_addr={addr} binds to a specific non-loopback interface; [security] admin_ip_allowlist restricts application-level access to {allowlist_desc}. Connections from other sources are rejected with 403 before reaching business logic, but the TCP port itself is still open on that interface's network (reachable for health checks / port probing). Narrow further by binding [api] listen_addr to 127.0.0.1 if remote admin access is not needed."
        ))],
        AdminBindScope::WildcardV4 | AdminBindScope::WildcardV6 => {
            let scope_desc = if scope == AdminBindScope::WildcardV4 {
                "every IPv4 interface of this host/container"
            } else {
                "every interface of this host/container (IPv4 and IPv6 alike on most kernels)"
            };
            if security.admin_ip_allowlist.is_empty() {
                vec![BroadcastLine::warn(format!(
                    "Admin API exposure: CRITICAL — [api] listen_addr={addr} binds to {scope_desc}, and [security] admin_ip_allowlist is empty, so ANY host that can reach this port (directly, or via a Docker port publish such as \"0.0.0.0:16827:9527\" in docker-compose.yml) can reach the management API. That API can rewrite WAF rules, upload WASM plugins, mint cluster-join tokens, and replace TLS certificates. The only gate is a JWT login (bootstrapped from the admin password printed once at first startup) — nothing stops every reachable IP from attempting to brute-force or exploit it. Fix by doing at least one of: set [security] admin_ip_allowlist to your trusted admin IP(s)/CIDR(s); bind [api] listen_addr to 127.0.0.1 for host-local-only access (pair with an SSH tunnel or reverse proxy for remote admin use); or, in Docker, keep the host port publish bound to 127.0.0.1 (see docker-compose.yml / .env ADMIN_BIND_ADDR) instead of publishing it on every host interface."
                ))]
            } else {
                vec![BroadcastLine::warn(format!(
                    "Admin API exposure: [api] listen_addr={addr} binds to {scope_desc}, but [security] admin_ip_allowlist restricts application-level access to {allowlist_desc}. Requests from any other source are rejected with 403 before reaching business logic, so the WAF-rule/plugin/cluster-token/certificate surface is gated. The TCP port itself is still open network-wide though (health checks, port scans, and the rate limiter's per-IP bucket can still be probed by anyone who can route to this host) — if those allowlist entries are not a hard perimeter (e.g. broad CIDRs, a shared NAT gateway), also consider binding [api] listen_addr to 127.0.0.1 or a specific admin-only interface."
                ))]
            }
        }
    }
}

/// Map `[storage]` into one retention policy per prunable table.
///
/// Every table in [`waf_storage::RetentionTable::ALL`] is represented, including
/// the ones an operator has switched off (`0`), so
/// [`retention_startup_broadcast`] can name them in its warning instead of
/// silently omitting them.
fn retention_policies(storage: &waf_common::config::StorageConfig) -> Vec<waf_storage::TableRetention> {
    use waf_storage::{RetentionTable, TableRetention};
    RetentionTable::ALL
        .iter()
        .map(|table| {
            let days = match table {
                RetentionTable::SemanticObservations => storage.semantic_observation_retention_days,
                RetentionTable::SecurityEvents => storage.security_event_retention_days,
                RetentionTable::AttackLogs => storage.attack_log_retention_days,
                RetentionTable::AuditLog => storage.audit_log_retention_days,
                RetentionTable::CrowdsecEvents => storage.crowdsec_event_retention_days,
                RetentionTable::CrowdsecDecisions => storage.crowdsec_decision_retention_days,
                RetentionTable::RefreshTokens => storage.refresh_token_retention_days,
                RetentionTable::NotificationLog => storage.notification_log_retention_days,
                RetentionTable::RequestStats => storage.request_stats_retention_days,
            };
            TableRetention::new(*table, days)
        })
        .collect()
}

/// Build the retention startup broadcast.
///
/// The operator-facing question at boot is: **which tables are being cleaned,
/// for how long, and when is the next sweep?** One INFO line answers that per
/// table; a WARN line per switched-off table names the personal data that will
/// now accumulate forever and the exact config key that re-enables cleanup.
fn retention_startup_broadcast(
    config: &waf_storage::RetentionConfig,
    policies: &[waf_storage::TableRetention],
) -> Vec<BroadcastLine> {
    let interval_hours = config.interval.as_secs() / 3600;
    let first_sweep_secs = config.initial_delay.as_secs();
    let (enabled, disabled): (Vec<&waf_storage::TableRetention>, Vec<&waf_storage::TableRetention>) =
        policies.iter().partition(|p| p.is_enabled());

    if enabled.is_empty() {
        return vec![BroadcastLine::warn(format!(
            "Retention pruner NOT STARTED — all {} observability tables are set to keep rows forever. Every table below grows without bound and retains client / admin IP addresses indefinitely: {}. Set a positive day count on any of them to start cleaning.",
            policies.len(),
            policies
                .iter()
                .map(|p| p.table.config_key())
                .collect::<Vec<_>>()
                .join(", ")
        ))];
    }

    let mut lines = vec![BroadcastLine::info(format!(
        "Retention pruner ACTIVE: {}/{} tables have a TTL, first sweep in {first_sweep_secs}s then every {interval_hours}h, deleting up to {} rows per DELETE batch",
        enabled.len(),
        policies.len(),
        config.batch_size
    ))];
    for policy in &enabled {
        lines.push(BroadcastLine::info(format!(
            "Retention: {} keeps {} days, then rows are deleted ({})",
            policy.table.name(),
            policy.retention_days,
            policy.table.contents()
        )));
    }
    for policy in &disabled {
        lines.push(BroadcastLine::warn(format!(
            "Retention DISABLED for {} ({}={}): the table grows without bound, and its rows — {} — are retained indefinitely. Set {} to a positive day count to clean it.",
            policy.table.name(),
            policy.table.config_key(),
            policy.retention_days,
            policy.table.contents(),
            policy.table.config_key()
        )));
    }
    lines
}

/// Shutdown guards that keep background-task sender halves alive.
///
/// Each field is a `tokio::sync::watch::Sender<bool>`.  Dropping this struct
/// closes the watch channel, which signals background workers to exit via
/// `changed().is_err()`.
struct ShutdownGuards {
    /// Keeps the `CrowdSec` background worker alive while the server runs.
    _crowdsec: Option<tokio::sync::watch::Sender<bool>>,
    /// Keeps the Community background worker alive while the server runs.
    _community: Option<tokio::sync::watch::Sender<bool>>,
    /// Keeps the observability-table retention pruner alive while the server
    /// runs.
    _retention: Option<tokio::sync::watch::Sender<bool>>,
}

/// Async initialization: database, engine, rules, Phases 5 & 6
type InitResult = (
    Arc<WafEngine>,
    Arc<HostRouter>,
    Arc<AppState>,
    Arc<ChallengeStore>,
    Arc<LoadBalancerRegistry>,
    Option<Arc<ResponseCache>>,
    ShutdownGuards,
    Option<Arc<waf_cluster::NodeState>>,
);

async fn init_async(config: &AppConfig) -> anyhow::Result<InitResult> {
    info!("Connecting to database...");
    let db = Arc::new(Database::connect(&config.storage.database_url, config.storage.max_connections).await?);

    info!("Running database migrations...");
    db.migrate().await?;

    // Compile the (already-validated) Lane 2 semantic config into the immutable
    // runtime form. `load_config` already ran strict validation; this resolves
    // detector-id strings and is a hard failure if it somehow fails.
    let content_security = RuntimeContentSecurityConfig::compile(&config.content_security)
        .map_err(|e| anyhow::anyhow!("invalid content_security config: {e}"))?;
    for line in content_security_startup_broadcast(&content_security, &config.content_security) {
        match line.level {
            BroadcastLevel::Info => info!("{}", line.text),
            BroadcastLevel::Warn => tracing::warn!("{}", line.text),
        }
    }

    // WAF engine
    let engine = Arc::new(WafEngine::new(
        Arc::clone(&db),
        WafEngineConfig {
            content_security,
            owasp: config.owasp.clone(),
            audit_log: config.audit_log.clone(),
            ..WafEngineConfig::default()
        },
    ));
    engine.reload_rules().await?;

    // GeoIP service
    if config.geoip.enabled {
        let policy = cache_policy_from_str(&config.geoip.cache_policy);
        match GeoIpService::init(&config.geoip.ipv4_xdb_path, &config.geoip.ipv6_xdb_path, policy) {
            Ok(service) => {
                info!("GeoIP service initialized");
                let service = Arc::new(service);
                engine.set_geoip(Arc::clone(&service));

                // Spawn background auto-updater if enabled.
                if config.geoip.auto_update.enabled {
                    let data_dir = std::path::PathBuf::from(&config.geoip.ipv4_xdb_path)
                        .parent()
                        .map_or_else(|| std::path::PathBuf::from("data"), std::path::Path::to_path_buf);

                    let handle = spawn_auto_updater(Arc::clone(&service), config.geoip.auto_update.clone(), data_dir);
                    // Keep the task alive for the process lifetime.
                    std::mem::forget(handle);

                    info!(
                        "GeoIP auto-updater spawned (interval: {})",
                        config.geoip.auto_update.interval
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to initialize GeoIP service: {}", e);
            }
        }
    }

    // Threat-intelligence IP feeds (opt-in; empty by default). Each enabled
    // feed becomes a background sync task that fetches its raw CIDR blocklist,
    // parses it, and folds the results into the WAF IP blacklist. Kept local
    // to init_async so the wiring lives beside the other background spawns.
    spawn_ip_feeds(config, &engine);

    // Host router
    let router = Arc::new(HostRouter::new());

    // Load hosts from database
    let hosts = db.list_hosts().await?;
    info!("Loading {} hosts from database", hosts.len());
    for host in &hosts {
        // Reuse the same Host -> HostConfig projection the API's create_host /
        // update_host handlers use, so the startup path can never drift from
        // the hot path (e.g. silently dropping log_only_mode on restart).
        let cfg = Arc::new(waf_api::handlers::host_runtime_config(host));
        router.register(&cfg);
    }

    // Register hosts from config file
    for entry in &config.hosts {
        use waf_common::HostConfig;
        let code = format!("cfg-{}", &uuid::Uuid::new_v4().to_string().replace('-', "")[..8]);
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
            // Multi-backend load balancing (empty → single-backend, unchanged).
            is_enable_load_balance: !entry.backends.is_empty(),
            load_balance_strategy: entry.load_balance_strategy.clone(),
            backends: entry.backends.clone(),
            // Per-host Lane1 detector toggles from the config file (defaults to
            // every detector on when the key is absent).
            defense_config: entry.defense_config.clone(),
            // Detect-only posture from the config file (defaults to enforce).
            log_only_mode: entry.log_only_mode,
            ..HostConfig::default()
        });
        router.register(&cfg);
    }

    info!("Registered {} host routes", router.len());

    // Build a load balancer for every host that declares a multi-backend pool.
    // Hosts without `backends` are absent from the registry and continue to use
    // their single `remote_host`/`remote_port` upstream (backward compatible).
    let lb_registry = Arc::new(LoadBalancerRegistry::new());
    for host in router.list() {
        if host.backends.is_empty() {
            continue;
        }
        let lb = Arc::new(LoadBalancer::from_backend_configs(
            host.load_balance_strategy.clone(),
            &host.backends,
        ));
        // Spawn a background TCP health checker for this pool (every 10s).
        let handle = spawn_health_checker(Arc::clone(&lb), std::time::Duration::from_secs(10));
        std::mem::forget(handle);
        lb_registry.register_arc(&host.code, lb);
        info!(
            "Load balancer active for host {} ({} backends, strategy {:?})",
            host.host,
            host.backends.len(),
            host.load_balance_strategy,
        );
    }

    // Build app state
    let mut api_state = AppState::new(Arc::clone(&db), Arc::clone(&engine), Arc::clone(&router))?;

    // Response cache. Built from config so the proxy and the management API
    // (cache stats / purge endpoints) share a single instance. When caching is
    // disabled the proxy receives `None` and behaves exactly as before.
    let response_cache = if config.cache.enabled {
        let cache = ResponseCache::new(
            config.cache.max_size_mb,
            config.cache.default_ttl_secs,
            config.cache.max_ttl_secs,
        );
        // Share the same cache with the API layer (stats/purge operate on it).
        api_state.cache = Arc::clone(&cache);
        info!(
            "Response cache enabled (max {} MiB, default TTL {}s, max TTL {}s)",
            config.cache.max_size_mb, config.cache.default_ttl_secs, config.cache.max_ttl_secs,
        );
        Some(cache)
    } else {
        info!("Response cache disabled");
        None
    };

    // Apply security configuration
    api_state.cors_origins = config.security.cors_origins.clone();
    api_state.security_config = config.security.clone();
    if config.security.api_rate_limit_rps > 0 {
        api_state.rate_limiter = Some(waf_api::security::ApiRateLimiter::new(
            config.security.api_rate_limit_rps,
        ));
    }

    // Login rate limiter: always enabled with a strict 10 req/s burst
    // to mitigate brute-force credential attacks on /api/auth/login
    api_state.login_rate_limiter = Some(waf_api::security::ApiRateLimiter::new(10));

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
            .load(waf_engine::plugins::manager::LoadPluginParams {
                id: p.id,
                name: p.name.clone(),
                version: p.version.clone(),
                description: p.description.clone().unwrap_or_default(),
                author: p.author.clone().unwrap_or_default(),
                enabled: p.enabled,
                wasm_bytes: &p.wasm_binary,
            })
            .await
        {
            tracing::warn!(plugin = %p.name, "Failed to load plugin: {e}");
        }
    }

    // Phase 5: load tunnel configs from DB
    let tunnels = db.list_tunnels().await.unwrap_or_default();
    info!("Loaded {} tunnel configs", tunnels.len());
    for t in &tunnels {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let tunnel_cfg = TunnelConfig {
            id: t.id,
            name: t.name.clone(),
            token_hash: t.token_hash.clone(),
            target_host: t.target_host.clone(),
            target_port: t.target_port as u16,
            enabled: t.enabled,
        };
        api_state.tunnel_registry.register(tunnel_cfg).await;
    }

    // Phase 6: CrowdSec integration
    let cs_config = app_config_to_crowdsec(config);
    let crowdsec_shutdown_guard = if cs_config.enabled {
        // Create a channel for graceful shutdown signal.
        // The sender is returned to the caller so it lives until the server
        // exits; dropping it signals the background worker to shut down.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        if let Some(components) = init_crowdsec(cs_config.clone(), shutdown_rx).await {
            info!(
                lapi_url = %cs_config.lapi_url,
                "CrowdSec integration active"
            );

            // Plug bouncer checker and AppSec client into the WAF engine
            engine.set_crowdsec(Arc::clone(&components.checker), components.appsec_client.clone());

            // Share cache and client with the API layer
            api_state.crowdsec_cache = Some(Arc::clone(&components.cache));
            api_state.crowdsec_client = Some(Arc::clone(&components.lapi_client));
            api_state.crowdsec_lapi_url = Some(cs_config.lapi_url.clone());

            // Keep the background task alive by holding its join handle inside
            // the components struct.  The sender is passed back to the caller.
            std::mem::forget(components);
            Some(shutdown_tx)
        } else {
            tracing::warn!("CrowdSec enabled in config but failed to initialise");
            None
        }
    } else {
        None
    };

    // Phase 8: Community threat intelligence sharing
    let community_shutdown_guard = if config.community.enabled {
        let community_config = waf_engine::community::config::CommunityConfig {
            enabled: config.community.enabled,
            server_url: config.community.server_url.clone(),
            api_key: config.community.api_key.clone(),
            machine_id: config.community.machine_id.clone(),
            public_key: config.community.public_key.clone(),
            batch_size: config.community.batch_size,
            flush_interval_secs: config.community.flush_interval_secs,
            sync_interval_secs: config.community.sync_interval_secs,
        };

        // Create a shutdown channel for community tasks.
        // The sender is returned to the caller so it lives until the server
        // exits; dropping it signals the community worker to shut down.
        let (community_shutdown_tx, community_shutdown_rx) = tokio::sync::watch::channel(false);

        if let Some(components) = init_community(community_config, community_shutdown_rx).await {
            info!(
                server_url = %config.community.server_url,
                "Community threat intelligence active"
            );

            // Plug community checker into the WAF engine
            engine.set_community(Arc::clone(&components.checker));

            // Plug community reporter into the WAF engine so detections
            // are automatically pushed to the community platform
            engine.set_community_reporter(Arc::clone(&components.reporter));

            // Share reporter with the API state for potential future use
            api_state.community_reporter = Some(Arc::clone(&components.reporter));

            // Keep background task join handles alive; sender is passed back.
            std::mem::forget(components);
            Some(community_shutdown_tx)
        } else {
            tracing::warn!("Community sharing enabled in config but failed to initialise");
            None
        }
    } else {
        None
    };

    // Retention / TTL enforcement for the observability tables. All five carry
    // an IP address (`semantic_observations`, `security_events`, `attack_logs`
    // and `crowdsec_events` a client IP; `audit_log` the admin's), and none of
    // them had a cleanup path, so without this they grow without bound and hold
    // personal data forever. One task sweeps every table on its own window. The
    // sender is returned to the caller so it lives until the server exits;
    // dropping it stops the pruner.
    let retention_shutdown_guard = {
        let retention = waf_storage::RetentionConfig::from_settings(
            config.storage.retention_prune_interval_hours,
            config.storage.retention_prune_batch_size,
        );
        let policies = retention_policies(&config.storage);
        for line in retention_startup_broadcast(&retention, &policies) {
            match line.level {
                BroadcastLevel::Info => info!("{}", line.text),
                BroadcastLevel::Warn => tracing::warn!("{}", line.text),
            }
        }
        let (retention_shutdown_tx, retention_shutdown_rx) = tokio::sync::watch::channel(false);
        waf_storage::spawn_retention_pruner(Arc::clone(&db), retention, &policies, retention_shutdown_rx).map(
            |handle| {
                // Keep the task alive for the process lifetime; shutdown is
                // driven by the watch sender held in `ShutdownGuards`.
                std::mem::forget(handle);
                retention_shutdown_tx
            },
        )
    };

    let guards = ShutdownGuards {
        _crowdsec: crowdsec_shutdown_guard,
        _community: community_shutdown_guard,
        _retention: retention_shutdown_guard,
    };

    // ACME / Let's Encrypt automatic TLS (M-3). Returns the shared challenge
    // store injected into the proxy so HTTP-01 probes can be answered; an empty
    // store when ACME is disabled.
    let acme_challenges = setup_acme(config, Arc::clone(&db), Arc::clone(&router)).await;

    // Phase 7: Cluster node state (shared with the API layer and the data plane).
    //
    // Built here — while `api_state` and `engine` are still in scope — so the two
    // rule-sync hooks can be wired onto the SAME `Arc<NodeState>` the cluster
    // thread will run:
    //   * Hook #1 (trigger): `AppState.cluster_state` lets admin rule writes call
    //     `record_rule_change` (Main-only) to broadcast to workers.
    //   * Hook #2 (consume): the engine reads synced rules from the shared
    //     `rule_registry`, so a worker's request path uses them without a DB.
    // On a standalone node (`[cluster]` absent or disabled) this stays `None`,
    // leaving both hooks inert and behaviour unchanged.
    let cluster_node_state = match config.cluster.clone().filter(|c| c.enabled) {
        Some(cluster_cfg) => match waf_cluster::NodeState::new(cluster_cfg, waf_cluster::StorageMode::Full) {
            Ok(state) => {
                let state = Arc::new(state);
                engine.attach_synced_registry(Arc::clone(&state.rule_registry));
                api_state.cluster_state = Some(Arc::clone(&state));
                info!("Cluster node state shared with API layer and data plane");
                Some(state)
            }
            Err(e) => {
                tracing::error!("Failed to initialise cluster node state: {e}");
                None
            }
        },
        None => None,
    };

    Ok((
        engine,
        router,
        Arc::new(api_state),
        acme_challenges,
        lb_registry,
        response_cache,
        guards,
        cluster_node_state,
    ))
}

/// Spawn background sync tasks for the configured threat-intelligence IP feeds.
///
/// No feed is active unless explicitly listed in `[[ip_feeds]]` (opt-in). Each
/// enabled entry is converted to the engine [`IpFeedSource`] type and handed a
/// dedicated task that refreshes on its interval; the task handles are detached
/// (`std::mem::forget`) to live for the process lifetime, matching the other
/// background spawns in `init_async`.
fn spawn_ip_feeds(config: &AppConfig, engine: &Arc<WafEngine>) {
    let feeds: Vec<IpFeedSource> = config
        .ip_feeds
        .iter()
        .filter(|f| f.enabled)
        .map(|f| IpFeedSource {
            name: f.name.clone(),
            url: f.url.clone(),
            format: IpFeedFormat::parse_str(&f.format),
            update_interval: std::time::Duration::from_secs(f.update_interval_secs),
        })
        .collect();

    if feeds.is_empty() {
        return;
    }

    info!("Spawning {} threat-intel IP-feed sync task(s)", feeds.len());
    let handles = spawn_ip_feed_sync(&engine.store, feeds);
    for handle in handles {
        std::mem::forget(handle);
    }
}

/// Wire up ACME automatic TLS: construct the `SslManager`, spawn the periodic
/// renewal task, and trigger one-time issuance for SSL hosts without an active
/// certificate. Returns the challenge store shared with the proxy.
///
/// The `SslManager` is constructed here (rather than in `run_server`) because
/// this is where the `Database` handle and populated `HostRouter` are in scope;
/// the background tasks are spawned on the caller's multi-threaded runtime,
/// which outlives `init_async` for the process lifetime.
async fn setup_acme(config: &AppConfig, db: Arc<Database>, router: Arc<HostRouter>) -> Arc<ChallengeStore> {
    if !config.acme.enabled {
        return Arc::new(ChallengeStore::new());
    }

    if config.acme.email.trim().is_empty() {
        tracing::warn!("ACME is enabled but [acme].email is empty; certificate issuance will fail");
    }

    let manager = Arc::new(SslManager::new(
        Arc::clone(&db),
        config.acme.email.clone(),
        config.acme.staging,
    ));
    let challenges = Arc::clone(&manager.challenges);

    // Periodic renewal task (interval clamped to a sane minimum).
    let interval = std::time::Duration::from_secs(config.acme.renewal_check_interval_secs.max(60));
    let renewal_handle = Arc::clone(&manager).spawn_renewal_task(interval);
    std::mem::forget(renewal_handle);
    info!(
        "ACME auto-renewal task spawned (check interval: {}s, staging: {})",
        interval.as_secs(),
        config.acme.staging
    );

    // One-time issuance for SSL hosts that have no active certificate yet.
    for host in router.list() {
        if !host.ssl {
            continue;
        }
        let has_active_cert = match db.list_certificates(Some(&host.code)).await {
            Ok(certs) => certs.iter().any(|c| c.status == "active" && c.cert_pem.is_some()),
            Err(e) => {
                tracing::warn!(domain = %host.host, "ACME: certificate lookup failed: {e}");
                // Treat a lookup failure as "already provisioned" to avoid
                // hammering the ACME API when the database is unavailable.
                true
            }
        };
        if has_active_cert {
            continue;
        }

        let mgr = Arc::clone(&manager);
        let host_code = host.code.clone();
        let domain = host.host.clone();
        tokio::spawn(async move {
            if let Err(e) = mgr.request_certificate(&host_code, &domain).await {
                // Log once per host; do not retry-spam the ACME endpoint.
                tracing::error!(domain = %domain, "ACME initial issuance failed: {e}");
            }
        });
    }

    challenges
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::content_security_config::ContentSecurityConfig;
    use waf_engine::crowdsec::config::FallbackAction;

    /// The shipped `configs/default.toml` Lane 2 section — the posture a real
    /// deployment boots with unless the operator edits it.
    fn shipped_content_security() -> ContentSecurityConfig {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/default.toml");
        load_config(path)
            .expect("shipped default.toml must load")
            .content_security
    }

    /// Compile a config and render the startup broadcast, as `init_async` does.
    fn broadcast(cfg: &ContentSecurityConfig) -> Vec<BroadcastLine> {
        let rt = RuntimeContentSecurityConfig::compile(cfg).expect("config must compile");
        content_security_startup_broadcast(&rt, cfg)
    }

    /// The verdict is always the last line.
    fn verdict(lines: &[BroadcastLine]) -> &BroadcastLine {
        lines.last().expect("broadcast is never empty")
    }

    #[test]
    fn shipped_default_broadcast_says_it_will_not_block() {
        // Shipped posture: lane enabled, global log_only, no overrides. The
        // operator must be told plainly that nothing is blocked.
        let lines = broadcast(&shipped_content_security());
        let v = verdict(&lines);
        assert_eq!(v.level, BroadcastLevel::Info, "shadow posture is not a warning");
        assert!(
            v.text.contains("WILL NOT BLOCK") && v.text.contains("no enabled attack family resolves to enforce"),
            "unexpected shipped verdict: {}",
            v.text
        );
        assert!(
            lines.iter().all(|l| l.level == BroadcastLevel::Info),
            "the shipped shadow posture must not warn"
        );
    }

    #[test]
    fn disabled_lane_broadcast_is_a_single_line() {
        let cfg = ContentSecurityConfig::default();
        let lines = broadcast(&cfg);
        assert_eq!(lines.len(), 1);
        let only = verdict(&lines);
        assert!(only.text.contains("DISABLED"), "{}", only.text);
        assert!(only.text.contains("WILL NOT BLOCK"), "{}", only.text);
    }

    #[test]
    fn global_off_reports_that_per_family_overrides_are_inert() {
        // A global `off` short-circuits the lane before detection, so even an
        // `enforce` override cannot block. The broadcast must say so rather than
        // list the override as enforcing.
        let mut cfg = shipped_content_security();
        cfg.enforcement_mode = "off".to_string();
        cfg.enforcement_overrides
            .insert("sql_injection".to_string(), "enforce".to_string());
        let lines = broadcast(&cfg);
        assert_eq!(lines.len(), 1);
        let only = verdict(&lines);
        assert_eq!(only.level, BroadcastLevel::Info);
        assert!(only.text.contains("does NO work"), "{}", only.text);
        assert!(only.text.contains("per-family overrides are inert"), "{}", only.text);
        assert!(only.text.contains("WILL NOT BLOCK"), "{}", only.text);
    }

    #[test]
    fn enforce_with_zero_rollout_warns_that_the_canary_gate_is_shut() {
        // The exact trap the old "not yet wired" WARN papered over: enforce is
        // real now, but the shipped rollout_bps=0 keeps it in shadow.
        let mut cfg = shipped_content_security();
        cfg.enforcement_mode = "enforce".to_string();
        cfg.rollout_bps = 0;
        let lines = broadcast(&cfg);
        let v = verdict(&lines);
        assert_eq!(v.level, BroadcastLevel::Warn, "an inert enforce config must warn");
        assert!(v.text.contains("WILL NOT BLOCK"), "{}", v.text);
        assert!(v.text.contains("rollout_bps=0"), "{}", v.text);
        assert!(
            !v.text.contains("NOT yet wired"),
            "the stale P1b shadow-only claim must be gone: {}",
            v.text
        );
    }

    #[test]
    fn enforce_with_rollout_warns_that_it_will_block() {
        let mut cfg = shipped_content_security();
        cfg.enforcement_mode = "enforce".to_string();
        cfg.rollout_bps = 1000;
        let lines = broadcast(&cfg);
        let v = verdict(&lines);
        assert_eq!(v.level, BroadcastLevel::Warn);
        assert!(v.text.contains("WILL BLOCK once warmed up"), "{}", v.text);
        // Warmup window == breaker.window (300s in the shipped config).
        assert!(v.text.contains("300s after process start"), "{}", v.text);
        // 1000 bps == 10% of client IPs.
        assert!(v.text.contains("10.00% canary"), "{}", v.text);
        // The per-request guardrails that startup cannot decide.
        assert!(v.text.contains("log_only_mode=true"), "{}", v.text);
        assert!(v.text.contains("enforce_safe"), "{}", v.text);
    }

    #[test]
    fn per_family_override_is_reported_as_the_only_enforcing_family() {
        let mut cfg = shipped_content_security();
        cfg.rollout_bps = 10_000;
        cfg.enforcement_overrides
            .insert("sql_injection".to_string(), "enforce".to_string());
        let lines = broadcast(&cfg);
        let families = lines
            .iter()
            .find(|l| l.text.contains("Lane 2 families — enforce"))
            .map(|l| l.text.clone())
            .expect("family breakdown line must be present");
        assert!(
            families.contains("enforce (a match may return 403): sql_injection;"),
            "{families}"
        );
        assert!(
            families.contains("rce"),
            "non-overridden families stay shadow: {families}"
        );
        let v = verdict(&lines);
        assert_eq!(v.level, BroadcastLevel::Warn);
        assert!(v.text.contains("WILL BLOCK once warmed up"), "{}", v.text);
        assert!(v.text.contains("[sql_injection]"), "{}", v.text);
        assert!(v.text.contains("100.00% canary"), "{}", v.text);
    }

    #[test]
    fn a_family_disabled_in_attacks_is_never_listed_as_enforcing() {
        // `[content_security.attacks.<family>].enabled = false` means the family
        // is never scored, so an `enforce` mode on it cannot block.
        let mut cfg = shipped_content_security();
        cfg.enforcement_mode = "enforce".to_string();
        cfg.rollout_bps = 10_000;
        for attack in cfg.attacks.values_mut() {
            attack.enabled = false;
        }
        let lines = broadcast(&cfg);
        let v = verdict(&lines);
        assert_eq!(v.level, BroadcastLevel::Info);
        assert!(
            v.text.contains("no enabled attack family resolves to enforce"),
            "{}",
            v.text
        );
    }

    #[test]
    fn appsec_failure_action_is_independent_of_fallback_action() {
        // Bouncer fails open, but AppSec is configured to fail closed. The two
        // must map to their own actions (H-4): AppSec no longer reuses the
        // top-level fallback_action.
        let mut config = AppConfig::default();
        config.crowdsec.fallback_action = "allow".to_string();
        config.crowdsec.appsec_endpoint = Some("http://127.0.0.1:7422".to_string());
        config.crowdsec.appsec_failure_action = "block".to_string();

        let cs = app_config_to_crowdsec(&config);
        assert_eq!(cs.fallback_action, FallbackAction::Allow);
        let appsec = cs.appsec.expect("appsec config should be present");
        assert_eq!(
            appsec.failure_action,
            FallbackAction::Block,
            "AppSec failure_action must come from its own field, not fallback_action"
        );
    }

    #[test]
    fn appsec_failure_action_defaults_to_allow() {
        // Backward compatibility: absent an explicit value, the default
        // ("allow") preserves the pre-H-4 fail-open behaviour.
        let mut config = AppConfig::default();
        config.crowdsec.fallback_action = "block".to_string();
        config.crowdsec.appsec_endpoint = Some("http://127.0.0.1:7422".to_string());
        // appsec_failure_action left at its default.

        let cs = app_config_to_crowdsec(&config);
        let appsec = cs.appsec.expect("appsec config should be present");
        assert_eq!(
            appsec.failure_action,
            FallbackAction::Allow,
            "default AppSec failure_action must remain Allow regardless of fallback_action"
        );
    }

    // ── admin API exposure startup broadcast ─────────────────────────────────

    fn api_cfg(listen_addr: &str) -> ApiConfig {
        ApiConfig {
            listen_addr: listen_addr.to_string(),
        }
    }

    fn security_cfg(allowlist: &[&str]) -> SecurityConfig {
        SecurityConfig {
            admin_ip_allowlist: allowlist.iter().map(|s| (*s).to_string()).collect(),
            ..SecurityConfig::default()
        }
    }

    /// Shipped `configs/default.toml` posture: `0.0.0.0:9527` + empty
    /// allowlist. This is the most dangerous combination and must WARN with
    /// enough detail that an operator understands both the exposure and the
    /// fix, not just "admin API is exposed".
    #[test]
    fn factory_default_wildcard_empty_allowlist_warns_critical() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("0.0.0.0:9527"), &security_cfg(&[]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(l.text.contains("CRITICAL"), "{}", l.text);
        assert!(l.text.contains("0.0.0.0:9527"), "{}", l.text);
        assert!(l.text.contains("admin_ip_allowlist"), "{}", l.text);
        assert!(l.text.contains("WAF rule"), "{}", l.text);
        assert!(l.text.contains("cluster-join tokens"), "{}", l.text);
        assert!(l.text.contains("TLS certificate"), "{}", l.text);
        assert!(l.text.contains("JWT"), "{}", l.text);
        assert!(l.text.contains("127.0.0.1"), "fix must name loopback bind: {}", l.text);
        assert!(
            l.text.contains("admin_ip_allowlist to your trusted admin"),
            "fix must name the allowlist config key: {}",
            l.text
        );
    }

    /// `0.0.0.0` with a populated allowlist: still open at the TCP level, but
    /// application access is gated. Must warn, but not with "CRITICAL".
    #[test]
    fn wildcard_with_allowlist_warns_but_notes_the_gate() {
        let lines =
            admin_exposure_startup_broadcast(&api_cfg("0.0.0.0:9527"), &security_cfg(&["10.0.0.5", "10.0.0.6"]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(!l.text.contains("CRITICAL"), "{}", l.text);
        assert!(l.text.contains("2 entries"), "{}", l.text);
        assert!(l.text.contains("10.0.0.5"), "{}", l.text);
        assert!(l.text.contains("10.0.0.6"), "{}", l.text);
        assert!(l.text.contains("rejected with 403"), "{}", l.text);
    }

    /// `127.0.0.1` with an empty allowlist: the safe default posture. Must
    /// stay INFO and explain why the empty allowlist is not itself a problem,
    /// while flagging the Docker port-publish caveat.
    #[test]
    fn loopback_empty_allowlist_is_informational() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("127.0.0.1:9527"), &security_cfg(&[]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Info, "{}", l.text);
        assert!(l.text.contains("loopback-only"), "{}", l.text);
        assert!(l.text.contains("docker-compose.yml"), "{}", l.text);
    }

    /// `127.0.0.1` with a populated allowlist: safe and the allowlist is
    /// redundant, but not misleading — say so.
    #[test]
    fn loopback_with_allowlist_notes_redundancy() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("127.0.0.1:9527"), &security_cfg(&["10.0.0.5"]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Info, "{}", l.text);
        assert!(l.text.contains("redundant"), "{}", l.text);
        assert!(l.text.contains("1 entry"), "{}", l.text);
    }

    /// A single-interface bind (neither loopback nor wildcard) with an empty
    /// allowlist must still warn: any host on that interface's network can
    /// reach the admin API.
    #[test]
    fn specific_interface_empty_allowlist_warns() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("10.0.0.5:9527"), &security_cfg(&[]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(l.text.contains("10.0.0.5:9527"), "{}", l.text);
    }

    /// An IPv6 wildcard bind is treated the same as the IPv4 wildcard case.
    #[test]
    fn ipv6_wildcard_empty_allowlist_warns_critical() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("[::]:9527"), &security_cfg(&[]));
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn);
        assert!(l.text.contains("CRITICAL"), "{}", l.text);
    }

    /// An unparseable `listen_addr` cannot be classified: warn rather than
    /// silently assuming a safe default.
    #[test]
    fn unparseable_listen_addr_warns_unknown() {
        let lines = admin_exposure_startup_broadcast(&api_cfg("not-a-valid-addr"), &security_cfg(&[]));
        assert_eq!(lines.len(), 1);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(l.text.contains("UNKNOWN"), "{}", l.text);
    }

    // ── retention startup broadcast ──────────────────────────────────────────

    /// Render the retention broadcast for a given `[storage]` section, exactly
    /// as `init_async` does.
    fn retention_broadcast(storage: &waf_common::config::StorageConfig) -> Vec<BroadcastLine> {
        let cfg = waf_storage::RetentionConfig::from_settings(
            storage.retention_prune_interval_hours,
            storage.retention_prune_batch_size,
        );
        retention_startup_broadcast(&cfg, &retention_policies(storage))
    }

    /// Join a broadcast into one searchable blob.
    fn rendered(lines: &[BroadcastLine]) -> String {
        lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn policies_cover_every_prunable_table_exactly_once() {
        let policies = retention_policies(&waf_common::config::StorageConfig::default());
        assert_eq!(
            policies.len(),
            waf_storage::RetentionTable::ALL.len(),
            "a table added to RetentionTable::ALL must also be mapped from [storage]"
        );
        for table in waf_storage::RetentionTable::ALL {
            let matched = policies.iter().filter(|p| p.table == table).count();
            assert_eq!(matched, 1, "{} must map to exactly one policy", table.name());
        }
    }

    #[test]
    fn shipped_defaults_give_every_table_a_positive_window() {
        // The whole point of the change: a stock deployment must not retain any
        // of these tables forever.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/default.toml");
        let storage = load_config(path).expect("shipped default.toml must load").storage;
        for policy in retention_policies(&storage) {
            assert!(
                policy.is_enabled(),
                "shipped default.toml leaves {} retaining rows forever",
                policy.table.name()
            );
        }
        // The audit trail must outlive the telemetry, not match it.
        assert!(
            storage.audit_log_retention_days > storage.security_event_retention_days,
            "the admin audit window must be longer than the attack-telemetry window"
        );
        assert!(
            storage.security_event_retention_days > storage.crowdsec_event_retention_days,
            "attack telemetry must outlive the third-party decision echo"
        );
    }

    #[test]
    fn the_broadcast_names_every_active_table_its_window_and_the_schedule() {
        let storage = waf_common::config::StorageConfig::default();
        let lines = retention_broadcast(&storage);
        let text = rendered(&lines);

        assert!(
            lines.iter().all(|l| l.level == BroadcastLevel::Info),
            "an all-enabled config must not warn: {text}"
        );
        assert!(text.contains("Retention pruner ACTIVE: 9/9 tables"), "{text}");
        // "when is the next sweep" must be answerable from the broadcast alone.
        assert!(text.contains("first sweep in 300s then every 6h"), "{text}");
        assert!(text.contains("up to 5000 rows per DELETE batch"), "{text}");

        for table in waf_storage::RetentionTable::ALL {
            assert!(
                text.contains(table.name()),
                "{} is missing from the broadcast: {text}",
                table.name()
            );
        }
        assert!(text.contains("security_events keeps 90 days"), "{text}");
        assert!(text.contains("audit_log keeps 365 days"), "{text}");
    }

    #[test]
    fn a_table_set_to_zero_warns_and_names_the_data_and_the_knob() {
        let storage = waf_common::config::StorageConfig {
            attack_log_retention_days: 0,
            ..waf_common::config::StorageConfig::default()
        };
        let lines = retention_broadcast(&storage);

        let warnings: Vec<&BroadcastLine> = lines.iter().filter(|l| l.level == BroadcastLevel::Warn).collect();
        assert_eq!(warnings.len(), 1, "exactly the disabled table warns");
        let warning = warnings.first().expect("one warning").text.as_str();
        assert!(warning.contains("Retention DISABLED for attack_logs"), "{warning}");
        assert!(
            warning.contains("storage.attack_log_retention_days=0"),
            "the warning must name the exact knob and its value: {warning}"
        );
        assert!(
            warning.contains("grows without bound"),
            "the warning must state the disk consequence: {warning}"
        );
        assert!(
            warning.contains("client_ip"),
            "the warning must state the personal data retained: {warning}"
        );

        // The eight still-enabled tables are unaffected and still announced.
        let text = rendered(&lines);
        assert!(text.contains("Retention pruner ACTIVE: 8/9 tables"), "{text}");
        assert!(text.contains("security_events keeps 90 days"), "{text}");
    }

    #[test]
    fn a_zeroed_table_is_never_swept() {
        // The broadcast warning and the scheduler must agree: a `0` table is
        // absent from the policy set the pruner actually runs.
        let storage = waf_common::config::StorageConfig {
            audit_log_retention_days: 0,
            ..waf_common::config::StorageConfig::default()
        };
        let enabled = waf_storage::retention::enabled_policies(&retention_policies(&storage));
        assert_eq!(enabled.len(), 8, "the zeroed table must not be swept");
        assert!(
            !enabled.iter().any(|p| p.table == waf_storage::RetentionTable::AuditLog),
            "audit_log was zeroed but is still in the sweep set"
        );
    }

    #[test]
    fn an_all_zero_config_warns_that_nothing_is_cleaned() {
        let storage = waf_common::config::StorageConfig {
            semantic_observation_retention_days: 0,
            security_event_retention_days: 0,
            attack_log_retention_days: 0,
            audit_log_retention_days: 0,
            crowdsec_event_retention_days: 0,
            crowdsec_decision_retention_days: 0,
            refresh_token_retention_days: 0,
            notification_log_retention_days: 0,
            request_stats_retention_days: 0,
            ..waf_common::config::StorageConfig::default()
        };
        let lines = retention_broadcast(&storage);
        assert_eq!(lines.len(), 1, "one decisive line, not five near-identical ones");
        let line = lines.first().expect("one line");
        assert_eq!(
            line.level,
            BroadcastLevel::Warn,
            "no retention at all must be a warning"
        );
        assert!(line.text.contains("Retention pruner NOT STARTED"), "{}", line.text);
        for table in waf_storage::RetentionTable::ALL {
            assert!(
                line.text.contains(table.config_key()),
                "{} is not named in the all-disabled warning: {}",
                table.name(),
                line.text
            );
        }
    }

    // ── startup restart wiring (regression: THIRD log_only_mode projection) ──
    //
    // `create_host`/`update_host` already share the `waf_api::handlers::
    // host_runtime_config` projection (regression-tested in waf-api). This
    // targets the third, previously-divergent projection: process startup,
    // which rebuilds the `HostRouter` from `Database::list_hosts` rather than
    // from a single handler's return value. Before this fix, `init_async`
    // hand-rolled its own `Host -> HostConfig` mapping that omitted
    // `log_only_mode`, so a host set to log-only through the admin API would
    // silently start BLOCKING again after every restart.
    //
    // This drives the actual restart sequence: persist a host row (as the
    // admin API would), reload it with the exact query `init_async` issues,
    // project it with the same helper the startup loop now calls, register it
    // into a fresh `HostRouter`, and feed a real `WafEngine` a malicious
    // request through the resolved config — proving the verdict itself (not
    // just a field copy) survives a restart.
    //
    // DB-gated like the engine/API suites. Run with:
    //   DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
    //     cargo test -p prx-waf -- --ignored --nocapture
    use std::collections::HashMap;
    use uuid::Uuid;
    use waf_common::{RequestCtx, WafAction};
    use waf_storage::models::Host;

    fn database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
    }

    /// Persist a host row with a unique hostname so parallel/repeated test
    /// runs never collide.
    ///
    /// This inserts directly rather than going through `Database::create_host`
    /// because that helper has an unrelated, pre-existing sqlx binding defect
    /// (out of scope for the `log_only_mode` wiring fixed here): it binds
    /// `remote_ip: Option<String>` as an explicitly-typed TEXT parameter
    /// against the `inet` column, which Postgres rejects whenever the value is
    /// `None` (column "`remote_ip`" is of type inet but expression is of type
    /// text). Every column this test doesn't care about (`remote_ip`
    /// included) is left to its schema default via `INSERT ... RETURNING *`.
    async fn seed_host(db: &Database, log_only_mode: bool) -> Host {
        let code = Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        let host = format!("logonly-restart-{}.test", Uuid::new_v4());
        sqlx::query_as::<_, Host>(
            r"INSERT INTO hosts (
                code, host, port, ssl, guard_status,
                remote_host, remote_port, start_status, log_only_mode
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *",
        )
        .bind(&code)
        .bind(&host)
        .bind(80_i32)
        .bind(false)
        .bind(true)
        .bind("127.0.0.1")
        .bind(8080_i32)
        .bind(true)
        .bind(log_only_mode)
        .fetch_one(db.pool())
        .await
        .expect("seed host row")
    }

    /// A malicious `SQLi` request bound to the reloaded runtime config. Benign
    /// User-Agent keeps header-phase scanner/bot detectors from firing ahead
    /// of the `SQLi` content detector.
    fn malicious_ctx(host_config: Arc<waf_common::HostConfig>) -> RequestCtx {
        let mut headers = HashMap::new();
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 (logonly-restart-wiring)".to_string(),
        );
        RequestCtx {
            req_id: "logonly-restart-wiring".to_string(),
            client_ip: "198.51.100.10".parse().expect("ip"),
            client_port: 54321,
            method: "GET".to_string(),
            host: host_config.host.clone(),
            port: host_config.port,
            path: "/".to_string(),
            query: "id=1 union select 1,2,3".to_string(),
            headers,
            body_preview: bytes::Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    /// Seed a host, then reload it exactly the way `init_async` does at
    /// process startup (`list_hosts` + the shared projection helper +
    /// `HostRouter::register`), and drive a live `WafEngine` with it.
    async fn restart_and_inspect(log_only_mode: bool) -> WafAction {
        let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
        db.migrate().await.expect("migrate");
        let seeded = seed_host(&db, log_only_mode).await;

        // Simulate a process restart: the only source of truth from here on is
        // what `list_hosts` returns, exactly like `init_async`.
        let reloaded = db.list_hosts().await.expect("list_hosts");
        let persisted = reloaded
            .iter()
            .find(|h| h.id == seeded.id)
            .expect("seeded host must survive the reload")
            .clone();

        let router = HostRouter::new();
        let cfg = Arc::new(waf_api::handlers::host_runtime_config(&persisted));
        router.register(&cfg);

        let resolved = router
            .resolve(&persisted.host)
            .expect("router must resolve the just-registered host");
        assert_eq!(
            resolved.log_only_mode, log_only_mode,
            "startup projection dropped log_only_mode across restart"
        );

        let engine_db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
        let engine = WafEngine::new(engine_db, WafEngineConfig::default());
        let mut ctx = malicious_ctx(resolved);
        let decision = engine.inspect(&mut ctx).await;

        let _ = db.delete_host(seeded.id).await;
        decision.action
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn restart_reload_of_log_only_true_downgrades_to_logonly() {
        let action = restart_and_inspect(true).await;
        assert!(
            matches!(action, WafAction::LogOnly),
            "log_only_mode=true host reloaded at startup must downgrade the SQLi Block to LogOnly, got {action:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn restart_reload_of_log_only_false_blocks() {
        let action = restart_and_inspect(false).await;
        assert!(
            matches!(action, WafAction::Block { status: 403, .. }),
            "log_only_mode=false host reloaded at startup must still Block the SQLi request, got {action:?}"
        );
    }

    // ── startup restart wiring (regression: per-host DefenseConfig projection) ──
    //
    // Companion to the `log_only_mode` restart tests above, for the newly-wired
    // `defense_json` → `HostConfig::defense_config` projection. Before this fix
    // both `host_runtime_config` and the config-file build path hard-coded
    // `..HostConfig::default()` for `defense_config`, so a host whose `sqli`
    // detector was turned off in the DB would silently re-enable it on every
    // restart. This seeds a host with `sqli = false`, reloads it exactly the way
    // `init_async` does, and proves a live `WafEngine` verdict honours the toggle
    // (allow, not block) after the restart — and conversely that `sqli = true`
    // still blocks.

    /// Seed a host row carrying a `defense_json` with the given `sqli` toggle
    /// (all other detectors left on). Inserts directly for the same reason
    /// `seed_host` does (unrelated `remote_ip`/inet binding defect).
    async fn seed_host_with_sqli(db: &Database, sqli: bool) -> Host {
        let code = Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
        let host = format!("defense-restart-{}.test", Uuid::new_v4());
        let defense = waf_common::DefenseConfig {
            sqli,
            ..waf_common::DefenseConfig::default()
        };
        sqlx::query_as::<_, Host>(
            r"INSERT INTO hosts (
                code, host, port, ssl, guard_status,
                remote_host, remote_port, start_status, log_only_mode, defense_json
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *",
        )
        .bind(&code)
        .bind(&host)
        .bind(80_i32)
        .bind(false)
        .bind(true)
        .bind("127.0.0.1")
        .bind(8080_i32)
        .bind(true)
        .bind(false)
        .bind(sqlx::types::Json(defense))
        .fetch_one(db.pool())
        .await
        .expect("seed host row")
    }

    /// Reload a `defense_json`-carrying host the way `init_async` does at
    /// startup and drive a live `WafEngine` with the resolved config.
    async fn restart_and_inspect_defense(sqli: bool) -> WafAction {
        let db = Database::connect(&database_url(), 5).await.expect("connect Postgres");
        db.migrate().await.expect("migrate");
        let seeded = seed_host_with_sqli(&db, sqli).await;

        let reloaded = db.list_hosts().await.expect("list_hosts");
        let persisted = reloaded
            .iter()
            .find(|h| h.id == seeded.id)
            .expect("seeded host must survive the reload")
            .clone();

        let router = HostRouter::new();
        let cfg = Arc::new(waf_api::handlers::host_runtime_config(&persisted));
        router.register(&cfg);

        let resolved = router
            .resolve(&persisted.host)
            .expect("router must resolve the just-registered host");
        assert_eq!(
            resolved.defense_config.sqli, sqli,
            "startup projection dropped defense_config.sqli across restart"
        );

        let engine_db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
        let engine = WafEngine::new(engine_db, WafEngineConfig::default());
        let mut ctx = malicious_ctx(resolved);
        let decision = engine.inspect(&mut ctx).await;

        let _ = db.delete_host(seeded.id).await;
        decision.action
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn restart_reload_of_sqli_disabled_allows_sqli_request() {
        let action = restart_and_inspect_defense(false).await;
        assert!(
            matches!(action, WafAction::Allow),
            "sqli-disabled host reloaded at startup must ALLOW the SQLi request, got {action:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn restart_reload_of_sqli_enabled_blocks_sqli_request() {
        let action = restart_and_inspect_defense(true).await;
        assert!(
            matches!(action, WafAction::Block { status: 403, .. }),
            "sqli-enabled host reloaded at startup must BLOCK the SQLi request, got {action:?}"
        );
    }
}
