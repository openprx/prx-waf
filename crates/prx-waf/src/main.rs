#![allow(clippy::print_stdout, clippy::print_stderr)]

mod upgrade;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use gateway::{
    ChallengeStore, HostRouter, LoadBalancer, LoadBalancerRegistry, ResponseCache, SslManager, TunnelConfig, WafProxy,
    spawn_health_checker,
};
use waf_api::notify_runtime::{MonitoredPool, NotifyRuntime};
use waf_api::{AppState, start_api_server};
use waf_common::config::{
    ApiConfig, AppConfig, ConfigError, SecurityConfig, WorkerThreadPlan, WorkerThreadSource, apply_env_overrides,
    load_config,
};
use waf_common::metrics::MetricsConfig;
use waf_engine::checks::ResponseCheckSet;
use waf_engine::{
    BUILTIN_BAD_BOTS, BUILTIN_GOOD_BOTS, BotAction, BotCheck, CrowdSecClient, CrowdSecConfig, EnforcementMode,
    ExportFormat, GeoIpService, IpFeedFormat, IpFeedSource, MAX_USER_PATTERNS, OWASPCheck, RuleDescriptor, RuleManager,
    RuleOverrideSpec, RuleState, RuntimeContentSecurityConfig, UserBotPattern, WafEngine, WafEngineConfig, XdbUpdater,
    cache_policy_from_str, export_registry, init_community, init_crowdsec, spawn_auto_updater, spawn_ip_feed_sync,
    validate_user_pattern,
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
    Run {
        /// Take the listening sockets over from a prx-waf already running on
        /// this host instead of binding fresh ones, so that changing the
        /// configuration or the binary does not drop connections.
        ///
        /// Start this process first; it waits on the handover socket. Then send
        /// `SIGQUIT` to the running process, which hands its listeners over and
        /// drains. If this process fails to start, nothing has been signalled
        /// yet and the running one keeps serving.
        ///
        /// A launch flag rather than a config setting, because it describes
        /// this one invocation: left in a file it would make every subsequent
        /// restart wait for a predecessor that is not there.
        #[arg(long)]
        upgrade: bool,
    },
    /// Run database migrations only
    Migrate,
    /// Seed the default admin user (admin / admin) if none exist
    SeedAdmin,
    /// `CrowdSec` integration management
    #[command(subcommand)]
    Crowdsec(CrowdSecCommands),
    /// Inspect the enforced rule set and override it (list, info, search,
    /// stats, export, enable, disable, validate)
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
    /// List the OWASP CRS rules this build enforces, with their effective state
    List {
        /// Filter by category (sqli, xss, rce, lfi, rfi, …)
        #[arg(long)]
        category: Option<String>,
        /// Filter by source file (substring of the path, e.g. "sqli")
        #[arg(long)]
        source: Option<String>,
        /// Filter by effective state: active | disabled | `log_only` | overridden
        #[arg(long)]
        state: Option<String>,
        /// Show the state in force for this host code instead of the global one
        #[arg(long)]
        host: Option<String>,
    },
    /// Show detailed information about a rule
    Info {
        /// Rule id, as `CRS-942100` or the bare upstream number `942100`
        rule_id: String,
        /// Show the state in force for this host code instead of the global one
        #[arg(long)]
        host: Option<String>,
    },
    /// Re-enable a rule that an override switched off or downgraded
    Enable {
        /// Rule id, as `CRS-942100` or the bare upstream number `942100`
        rule_id: String,
        /// Scope to one host code instead of every host
        #[arg(long)]
        host: Option<String>,
        /// Why (stored with the override)
        #[arg(long)]
        note: Option<String>,
        /// Delete the override outright instead of storing an explicit "on"
        #[arg(long)]
        clear: bool,
    },
    /// Stop a rule from blocking — either entirely, or by downgrading it to
    /// record-only
    Disable {
        /// Rule id, as `CRS-942100` or the bare upstream number `942100`
        rule_id: String,
        /// Scope to one host code instead of every host
        #[arg(long)]
        host: Option<String>,
        /// Why (stored with the override)
        #[arg(long)]
        note: Option<String>,
        /// Keep evaluating the rule and keep writing every match to the audit
        /// log, but stop it contributing to the anomaly score. This is the
        /// safe way to measure a rule's false positives; a full disable is a
        /// detection the WAF stops performing.
        #[arg(long)]
        log_only: bool,
    },
    /// Not implemented — prints how to make an override take effect and exits
    /// non-zero
    Reload,
    /// Validate a rule file without loading it
    Validate {
        /// Path to the rule file
        path: PathBuf,
    },
    /// Not implemented — prints where a rule can actually be added and exits
    /// non-zero
    Import {
        /// File path or HTTP(S) URL
        source: String,
    },
    /// Write the enforced rule inventory to stdout as YAML or JSON — the same
    /// set `rules list` prints, in a form a script or a diff can read
    Export {
        /// Output format: yaml (default) or json
        #[arg(long, default_value = "yaml")]
        format: String,
        /// Export the states in force for this host code instead of the global
        /// ones
        #[arg(long)]
        host: Option<String>,
    },
    /// Not implemented — prints why remote rule feeds are refused and exits
    /// non-zero
    Update,
    /// Search the enforced rules by id, name, category, or source file
    Search {
        /// Case-insensitive substring, matched against id, CRS id, name,
        /// category and source file
        query: String,
        /// Show the state in force for this host code instead of the global one
        #[arg(long)]
        host: Option<String>,
    },
    /// Summarise the rules this build enforces and the overrides on them
    Stats {
        /// Count the states in force for this host code instead of the global
        /// ones
        #[arg(long)]
        host: Option<String>,
    },
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
    /// List bot signatures: the compiled-in catalogue plus operator patterns
    List,
    /// Add an operator bot pattern (stored in the database)
    Add {
        /// Regex pattern to match against User-Agent
        pattern: String,
        /// Action: block | allow
        #[arg(long, default_value = "block")]
        action: String,
        /// Short label shown in listings (defaults to the pattern)
        #[arg(long)]
        name: Option<String>,
        /// Free-form note about why this pattern exists
        #[arg(long)]
        description: Option<String>,
    },
    /// Remove an operator bot pattern by numeric id or exact pattern text
    Remove {
        /// Numeric id (the digits after `BOT-USER-`) or the exact pattern
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

    let cli = Cli::parse();

    let filter =
        EnvFilter::from_default_env().add_directive(tracing_subscriber::filter::Directive::from(tracing::Level::INFO));
    // Colour only when a human is watching. `fmt::layer()` turns ANSI on
    // unconditionally, and the escapes land *between the field name and its
    // `=`* — a line reading `action="block"` on screen is
    // `\e[3maction\e[0m\e[2m=\e[0m"block"` in the file, so `grep 'action="block"'`
    // over a redirected log, a container log or a journal finds nothing. That
    // grep is the entire point of the structured fields the refusal paths now
    // carry (`docs/logs-and-metrics.md` §1), so a decoration that breaks it is
    // not a cosmetic default. Piped output is machine-read by definition;
    // a terminal is not.
    let ansi = std::io::IsTerminal::is_terminal(&std::io::stdout());
    // `rules export` writes a machine-readable document to stdout. A log line
    // interleaved into it would make `rules export > rules.json` produce a file
    // that does not parse, so this one command's logs join its summary on
    // stderr. Every other command keeps logging to stdout.
    if matches!(&cli.command, Commands::Rules(RulesCommands::Export { .. })) {
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
            )
            .with(filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(ansi))
            .with(filter)
            .init();
    }

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
        Commands::Run { upgrade } => {
            run_server(&config, upgrade)?;
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
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run_bot_cmd(sub, &config))?;
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
        RulesCommands::List {
            category,
            source,
            state,
            host,
        } => {
            let (checker, db_note) = live_rule_registry(config).await;
            let mut rules = checker.registry(host.as_deref());
            if let Some(cat) = &category {
                rules.retain(|r| r.category.eq_ignore_ascii_case(cat));
            }
            if let Some(src) = &source {
                rules.retain(|r| r.source.contains(src.as_str()));
            }
            if let Some(want) = &state {
                let want = want.trim().to_ascii_lowercase();
                rules.retain(|r| match want.as_str() {
                    "overridden" => r.state != RuleState::Active,
                    other => r.state.as_str() == other,
                });
            }

            print_rule_table(&rules);
            print_rule_totals(&rules, host.as_deref(), "listed");
            print_degraded_warning(&checker);
            if let Some(note) = db_note {
                println!("{note}");
            }
        }

        RulesCommands::Info { rule_id, host } => {
            let (checker, db_note) = live_rule_registry(config).await;
            let wanted = rule_id.trim();
            let rules = checker.registry(host.as_deref());
            let found = rules
                .iter()
                .find(|r| r.id == wanted || r.crs_id.is_some_and(|id| id.to_string() == wanted));
            if let Some(rule) = found {
                println!("ID:          {}", rule.id);
                if let Some(crs_id) = rule.crs_id {
                    println!("CRS id:      {crs_id}");
                }
                println!("Name:        {}", rule.name);
                println!("Category:    {}", rule.category);
                println!("Source:      {}", rule.source);
                println!("Severity:    {} (+{} to the anomaly score)", rule.severity, rule.score);
                println!("Paranoia:    {}", rule.paranoia);
                println!("Phase:       {}", rule.phase);
                println!("Declared:    {}", rule.declared_action);
                println!(
                    "State:       {} ({})",
                    rule.state.as_str(),
                    host.as_deref()
                        .map_or_else(|| "global".to_owned(), |h| format!("host {h}")),
                );
            } else {
                println!("Rule not found in the loaded set: {rule_id}");
                println!("`prx-waf rules list` shows every rule this build enforces.");
            }
            if let Some(note) = db_note {
                println!("{note}");
            }
        }

        RulesCommands::Enable {
            rule_id,
            host,
            note,
            clear,
        } => {
            write_rule_override(
                config,
                &rule_id,
                host.as_deref(),
                note,
                RuleOverrideWrite::Enable { clear },
            )
            .await?;
        }

        RulesCommands::Disable {
            rule_id,
            host,
            note,
            log_only,
        } => {
            write_rule_override(
                config,
                &rule_id,
                host.as_deref(),
                note,
                RuleOverrideWrite::Disable { log_only },
            )
            .await?;
        }

        RulesCommands::Reload => {
            let api = admin_api_origin(&config.api.listen_addr);
            anyhow::bail!(
                "`rules reload` is not implemented — nothing was reloaded, and no running process \
                 was contacted.\n\
                 There is nothing here to reload. A serving `prx-waf run` compiles its OWASP CRS \
                 set once at startup from `rules/owasp-crs/` and never re-reads those files, and \
                 it keeps its operator overrides in its own memory, rebuilt from the database. \
                 This command holds neither.\n\n\
                 To apply `rules enable` / `rules disable` (or any out-of-band edit of \
                 `rule_overrides`) to a running proxy:\n\
                 \x20 curl -X POST {api}/api/rules/reload -H 'Authorization: Bearer <admin JWT>'\n\
                 That endpoint rebuilds the override layer in place, with no dropped connections, \
                 and reports how many rules ended up disabled or log-only. The Admin UI does the \
                 same on every rule change.\n\n\
                 To pick up an edited file under `rules/owasp-crs/`, restart the process: the CRS \
                 automata are built at startup and are not rebuilt under live traffic.\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
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
            let api = admin_api_origin(&config.api.listen_addr);
            anyhow::bail!(
                "`rules import` is not implemented — nothing was imported, nothing was written to \
                 disk or to the database, and no running process was contacted.\n\
                 What it did was parse {source} into a rule registry this command owned, print a \
                 count, and exit, discarding every rule it had just read. There is no store behind \
                 it: `[rules]`, the section it read, is not consulted by the serving process at \
                 all.\n\n\
                 To check that a rule file parses — which is all this command ever really did:\n\
                 \x20 prx-waf rules validate {source}\n\n\
                 To add a detection this WAF actually enforces:\n\
                 \x20 * an OWASP CRS rule: put the YAML file under `rules/owasp-crs/` on every \
                 node and restart. That directory is a hardcoded path compiled once at startup — \
                 there is no import step for it and no live reload.\n\
                 \x20 * anything operator-managed (custom rules, IP/URL lists, bot patterns, \
                 sensitive-data patterns): POST it to the admin API, which stores it and applies \
                 it immediately, e.g.\n\
                 \x20     curl -X POST {api}/api/custom-rules -H 'Authorization: Bearer <admin \
                 JWT>' -H 'Content-Type: application/json' -d @rule.json\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }

        RulesCommands::Export { format, host } => {
            let Some(fmt) = ExportFormat::parse_flag(&format) else {
                anyhow::bail!(
                    "unknown export format {format:?} — nothing was written. Supported: \
                     `yaml` (the default) and `json`."
                );
            };
            let (checker, db_note) = live_rule_registry(config).await;
            let rules = checker.registry(host.as_deref());
            print!("{}", export_registry(&rules, fmt)?);

            // Everything that is not the inventory goes to stderr, so
            // `rules export > rules.json` stays a parseable document while the
            // operator still sees the caveats.
            let (active, disabled, log_only) = state_counts(&rules);
            eprintln!(
                "{} enforced rule(s) exported as {} — {active} active, {disabled} disabled, \
                 {log_only} log-only. Scope: {}.",
                rules.len(),
                fmt.as_str(),
                scope_label(host.as_deref()),
            );
            if let Some(warning) = degraded_warning(&checker) {
                eprintln!("{warning}");
            }
            if let Some(note) = db_note {
                eprintln!("{note}");
            }
        }

        RulesCommands::Update => {
            let api = admin_api_origin(&config.api.listen_addr);
            let configured = if config.rules.sources.is_empty() {
                "There are no `[[rules.sources]]` entries in this config, so it had nothing to \
                 fetch in any case."
                    .to_owned()
            } else {
                let rows: Vec<String> = config
                    .rules
                    .sources
                    .iter()
                    .map(|src| {
                        let location = src.url.as_deref().or(src.path.as_deref()).unwrap_or("(none)");
                        format!("   {:<20} {location}", src.name)
                    })
                    .collect();
                format!(
                    "The entries it would have fetched (inert — nothing but this message and \
                     `sources list` reads them):\n{}",
                    rows.join("\n")
                )
            };
            anyhow::bail!(
                "`rules update` is not implemented — nothing was fetched, nothing was written, and \
                 no running process was contacted.\n\
                 What it did was download every `[[rules.sources]]` URL into a rule registry this \
                 command owned, print a count per source, and exit, discarding all of it. \
                 {configured}\n\n\
                 It is withheld rather than merely unfinished. A remote rule feed is a supply \
                 chain: whoever controls that URL controls what this WAF detects, and a single \
                 fetched rule is enough to turn it into a deny-all (a `.*` pattern on every \
                 request) or to quietly retire a detection class. Pinning, signature verification \
                 and review-before-apply are not designed yet, so the fetch does not happen at all \
                 rather than happening unchecked.\n\n\
                 To change what this WAF enforces today:\n\
                 \x20 * OWASP CRS: edit or add YAML under `rules/owasp-crs/` and restart.\n\
                 \x20 * operator-managed rules: use the admin API at {api} (or the Admin UI) — \
                 those take effect immediately.\n\
                 \x20 * to switch one CRS rule off or down: `prx-waf rules disable <id>` \
                 [--log-only], then `curl -X POST {api}/api/rules/reload`.\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }

        RulesCommands::Search { query, host } => {
            let (checker, db_note) = live_rule_registry(config).await;
            let needle = query.trim().to_ascii_lowercase();
            let hits: Vec<RuleDescriptor> = checker
                .registry(host.as_deref())
                .into_iter()
                .filter(|rule| rule_matches_query(rule, &needle))
                .collect();

            if hits.is_empty() {
                println!(
                    "No enforced rule matches '{query}'. The search covers rule id, upstream CRS \
                     id, name, category and source file; `prx-waf rules list` shows every rule \
                     this build enforces."
                );
            } else {
                print_rule_table(&hits);
                print_rule_totals(&hits, host.as_deref(), &format!("matched '{query}'"));
            }
            print_degraded_warning(&checker);
            if let Some(note) = db_note {
                println!("{note}");
            }
        }

        RulesCommands::Stats { host } => {
            let (checker, db_note) = live_rule_registry(config).await;
            let rules = checker.registry(host.as_deref());
            let summary = checker.load_summary();
            let (active, disabled, log_only) = state_counts(&rules);

            println!("Rule statistics — scope: {}", scope_label(host.as_deref()));
            println!("{}", "-".repeat(60));
            println!(
                "  Declared:  {:>5}  (rules read from rules/owasp-crs/)",
                summary.attempted
            );
            println!(
                "  Enforced:  {:>5}  (compiled into a matcher this WAF runs)",
                rules.len()
            );
            println!(
                "  Rejected:  {:>5}  (declared but not enforced){}",
                summary.rejected.len(),
                if summary.used_embedded_fallback {
                    "; the minimal embedded rule set was substituted"
                } else {
                    ""
                }
            );
            println!("  Request:   {:>5}", phase_count(&rules, "request"));
            println!("  Response:  {:>5}", phase_count(&rules, "response"));
            println!();
            println!("Effective state (of the {} enforced):", rules.len());
            println!("  Active:    {active:>5}");
            println!(
                "  Disabled:  {disabled:>5}  (not evaluated — each one is a detection this WAF no \
                 longer performs)"
            );
            println!("  Log-only:  {log_only:>5}  (evaluated and audited, contributing no score)");

            print_grouped("By category", &rules, |rule| rule.category.as_str());
            print_grouped("By severity", &rules, |rule| rule.severity);
            print_grouped("By source file", &rules, |rule| rule.source.as_str());

            if !summary.source_errors.is_empty() {
                println!("\nUnreadable source(s):");
                for err in &summary.source_errors {
                    println!("  {}: {}", err.source, err.error);
                }
            }
            print_degraded_warning(&checker);
            if let Some(note) = db_note {
                println!("{note}");
            }
        }
    }

    Ok(())
}

// ── Sources commands ──────────────────────────────────────────────────────────

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
            anyhow::bail!(
                "`sources add` is not implemented — nothing was written.\n\
                 There is no writable rule-source store; `[[rules.sources]]` lives in the config \
                 file only. Add the entry yourself and restart:\n\n\
                 \x20 [[rules.sources]]\n\
                 \x20 name   = \"{name}\"\n\
                 \x20 url    = \"{url}\"\n\
                 \x20 format = \"{format}\"\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }
        SourcesCommands::Remove { name } => {
            anyhow::bail!(
                "`sources remove` is not implemented — source '{name}' was not touched.\n\
                 Delete its `[[rules.sources]]` entry from the config file and restart.\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }
        SourcesCommands::Update { name } => {
            let which = name.as_deref().unwrap_or("all sources");
            anyhow::bail!(
                "`sources update` is not implemented — '{which}' was not fetched.\n\
                 {NO_REMOTE_RULE_FETCH}\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }
        SourcesCommands::Sync => {
            anyhow::bail!(
                "`sources sync` is not implemented — nothing was fetched.\n\
                 {NO_REMOTE_RULE_FETCH}\n\n\
                 {RULE_SOURCES_ARE_CLI_ONLY}"
            );
        }
    }
    Ok(())
}

/// What every mutating `rules` sub-command has to say.
///
/// The CLI writes to the database directly; a `prx-waf run` process already
/// serving traffic is holding its own override snapshot and will not notice.
/// Saying "disabled" without saying this is how an operator ends up believing a
/// rule is off when it is still blocking.
const RULE_OVERRIDE_RELOAD_NOTE: &str = "A running proxy keeps its current override snapshot until it reloads. Apply it with \
     `POST /api/rules/reload` (or `POST /api/reload`), or restart the process. Changes made \
     through the Admin UI / `POST /api/rules/overrides` take effect immediately and need none of \
     this.";

/// Which scope a `rules` read is reporting on, spelled the one way.
fn scope_label(host: Option<&str>) -> String {
    host.map_or_else(|| "global".to_owned(), |code| format!("host {code}"))
}

/// Active / disabled / log-only, counted once.
///
/// `rules list`, `rules search` and `rules stats` all print these three numbers
/// and `GET /api/rules/registry` returns the last two. Deriving them in one
/// place is what stops one question getting three answers.
fn state_counts(rules: &[RuleDescriptor]) -> (usize, usize, usize) {
    let disabled = rules.iter().filter(|r| r.state == RuleState::Disabled).count();
    let log_only = rules.iter().filter(|r| r.state == RuleState::LogOnly).count();
    let active = rules.len().saturating_sub(disabled).saturating_sub(log_only);
    (active, disabled, log_only)
}

/// Rules evaluated in `phase` (`request` / `response`), matching the
/// `request_rules` / `response_rules` fields of `GET /api/rules/registry`.
fn phase_count(rules: &[RuleDescriptor], phase: &str) -> usize {
    rules.iter().filter(|r| r.phase == phase).count()
}

/// Does this rule answer a `rules search` query?
///
/// Matched against the identifying fields the listing prints: the engine id,
/// the upstream CRS number an operator reads off a log line, the rule name, its
/// category, and the file it came from. A loaded rule carries no free-text
/// description — there is nothing else to search.
fn rule_matches_query(rule: &RuleDescriptor, needle: &str) -> bool {
    rule.id.to_ascii_lowercase().contains(needle)
        || rule.crs_id.is_some_and(|id| id.to_string().contains(needle))
        || rule.name.to_ascii_lowercase().contains(needle)
        || rule.category.to_ascii_lowercase().contains(needle)
        || rule.source.to_ascii_lowercase().contains(needle)
}

/// The rule table `rules list` and `rules search` both print.
fn print_rule_table(rules: &[RuleDescriptor]) {
    println!(
        "{:<16} {:<44} {:<10} {:<9} {:<3} {:<9} {:<9} State",
        "ID", "Name", "Category", "Severity", "PL", "Phase", "Declared"
    );
    println!("{}", "-".repeat(120));
    for rule in rules {
        println!(
            "{:<16} {:<44} {:<10} {:<9} {:<3} {:<9} {:<9} {}",
            truncate(&rule.id, 15),
            truncate(&rule.name, 43),
            truncate(&rule.category, 9),
            rule.severity,
            rule.paranoia,
            rule.phase,
            rule.declared_action,
            rule.state.as_str(),
        );
    }
}

/// The one-line total under that table. `verb` says what produced the rows
/// ("listed", "matched 'sqli'").
fn print_rule_totals(rules: &[RuleDescriptor], host: Option<&str>, verb: &str) {
    let (active, disabled, log_only) = state_counts(rules);
    println!(
        "\n{} rule(s) {verb} — {active} active, {disabled} disabled, {log_only} log-only. Scope: {}.",
        rules.len(),
        scope_label(host),
    );
}

/// Count the rules by one field and print the breakdown, largest bucket first.
fn print_grouped<F>(title: &str, rules: &[RuleDescriptor], key: F)
where
    F: Fn(&RuleDescriptor) -> &str,
{
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for rule in rules {
        *counts.entry(key(rule)).or_default() += 1;
    }
    let mut rows: Vec<(&str, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    println!("\n{title}:");
    for (label, count) in rows {
        println!("  {:<44} {count:>5}", truncate(label, 43));
    }
}

/// Say so when part of the declared rule set is not being enforced.
///
/// Carried by every `rules` read: a listing that silently omits rules the load
/// threw away reads as a complete inventory of a WAF that is smaller than the
/// operator thinks it is. `None` when the whole declared set is enforced.
fn degraded_warning(checker: &OWASPCheck) -> Option<String> {
    let summary = checker.load_summary();
    if !summary.is_degraded() {
        return None;
    }
    Some(format!(
        "WARNING: {} of {} declared rule(s) are NOT enforced ({} unreadable source(s)){}.",
        summary.rejected.len(),
        summary.attempted,
        summary.source_errors.len(),
        if summary.used_embedded_fallback {
            "; the minimal embedded rule set was substituted"
        } else {
            ""
        }
    ))
}

/// [`degraded_warning`] on stdout, for the reads that print a report there.
///
/// `rules export` writes the inventory to stdout and so prints its copy on
/// stderr instead.
fn print_degraded_warning(checker: &OWASPCheck) {
    if let Some(warning) = degraded_warning(checker) {
        println!("{warning}");
    }
}

/// The origin an operator can actually `curl` the management API on.
///
/// `[api] listen_addr` is a bind address: `0.0.0.0:9527` is where the server
/// listens, not an address a client connects to. Printing it verbatim in a
/// copy-pasteable command would hand out one that fails on some platforms, so
/// an unspecified bind is reported as loopback.
fn admin_api_origin(listen_addr: &str) -> String {
    match listen_addr.parse::<std::net::SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => format!("http://127.0.0.1:{}", addr.port()),
        Ok(addr) => format!("http://{addr}"),
        // Not a socket address: echo it back rather than invent one.
        Err(_) => format!("http://{listen_addr}"),
    }
}

/// Build the rule set the daemon would build, so every `rules` read — `list`,
/// `info`, `search`, `stats` — answers "what is this WAF enforcing" and not
/// "what is in some file".
///
/// [`OWASPCheck::new`] reads `rules/owasp-crs/` relative to the working
/// directory — the same hardcoded path the serving process uses — so running
/// the CLI from the deployment root gives the deployment's rule set. The
/// overrides are then layered on from the database.
///
/// The second return value is a warning to print when the database could not be
/// consulted: the listing is still useful (it is the whole declared rule set),
/// but the *state* column would then be the declared one rather than the
/// effective one, and an operator has to be told which they are looking at.
async fn live_rule_registry(config: &AppConfig) -> (OWASPCheck, Option<String>) {
    let checker = OWASPCheck::new().with_config(&config.owasp);
    let db = match waf_storage::Database::connect(&config.storage.database_url, config.storage.max_connections).await {
        Ok(db) => db,
        Err(e) => {
            return (
                checker,
                Some(format!(
                    "NOTE: the database could not be reached ({e}), so operator overrides were not \
                     read. Every state above is the rule's DECLARED state, which is not necessarily \
                     what the running proxy is doing."
                )),
            );
        }
    };
    let rows = match db.list_rule_overrides().await {
        Ok(rows) => rows,
        Err(e) => {
            return (
                checker,
                Some(format!(
                    "NOTE: rule_overrides could not be read ({e}); the states above are the declared \
                     ones."
                )),
            );
        }
    };
    let specs: Vec<RuleOverrideSpec> = rows
        .into_iter()
        .filter(|row| row.host_id.is_none() || row.host_code.is_some())
        .filter_map(|row| {
            RuleState::from_row(row.enabled, row.action_override.as_deref())
                .ok()
                .map(|state| RuleOverrideSpec {
                    rule_id: row.rule_id,
                    host_code: row.host_code,
                    state,
                })
        })
        .collect();
    checker.load_overrides(&specs);
    (checker, None)
}

/// Which way `rules enable` / `rules disable` moves one rule.
enum RuleOverrideWrite {
    /// `--clear` deletes the override outright; otherwise an explicit "on" is
    /// stored, which is what cancels a *global* disable for one host.
    Enable { clear: bool },
    /// `--log-only` keeps the rule running and recorded; without it the rule is
    /// not evaluated at all.
    Disable { log_only: bool },
}

/// Write one `rule_overrides` row, having first checked the rule exists.
///
/// The id is resolved against the rule set this build actually loads before
/// anything is written, so a typo is a non-zero exit rather than a row that
/// silently never applies — the same check `POST /api/rules/overrides` runs.
async fn write_rule_override(
    config: &AppConfig,
    rule_id: &str,
    host: Option<&str>,
    note: Option<String>,
    write: RuleOverrideWrite,
) -> anyhow::Result<()> {
    let rule_id = rule_id.trim();
    let checker = OWASPCheck::new();
    if !checker.knows_rule(rule_id) {
        anyhow::bail!(
            "unknown rule id {rule_id:?} — nothing was written. It is not in the rule set this \
             build loads from `rules/owasp-crs/` (run this command from the deployment root). \
             `prx-waf rules list` shows every enforced rule; ids are accepted as \"CRS-942100\" or \
             as the bare upstream number \"942100\"."
        );
    }

    let db = waf_storage::Database::connect(&config.storage.database_url, config.storage.max_connections).await?;
    if let Some(code) = host
        && db.get_host_by_code(code).await?.is_none()
    {
        anyhow::bail!(
            "unknown host code {code:?} — nothing was written. An override can only be scoped to a \
             host in the database; hosts declared in the config file get a fresh code on every \
             start and can only be governed by a global override (omit --host)."
        );
    }

    let scope = host.map_or_else(|| "every host".to_owned(), |code| format!("host {code}"));
    let (enabled, action_override, outcome) = match write {
        RuleOverrideWrite::Enable { clear: true } => {
            let rows = db.list_rule_overrides().await?;
            let Some(row) = rows
                .iter()
                .find(|r| r.rule_id == rule_id && r.host_code.as_deref() == host)
            else {
                println!("No override for {rule_id} in scope '{scope}' — the rule already runs as declared.");
                return Ok(());
            };
            db.delete_rule_override(row.id).await?;
            println!("Override for {rule_id} removed from scope '{scope}': the rule runs as declared again.");
            println!("{RULE_OVERRIDE_RELOAD_NOTE}");
            return Ok(());
        }
        RuleOverrideWrite::Enable { clear: false } => (
            Some(true),
            None,
            format!("{rule_id} is now explicitly ACTIVE for {scope}."),
        ),
        RuleOverrideWrite::Disable { log_only: true } => (
            None,
            Some("log".to_owned()),
            format!(
                "{rule_id} is now LOG-ONLY for {scope}: it keeps running and every match is written \
                 to the audit log, but it contributes nothing to the anomaly score, so it can no \
                 longer block on its own or help another rule reach the threshold."
            ),
        ),
        RuleOverrideWrite::Disable { log_only: false } => (
            Some(false),
            None,
            format!(
                "{rule_id} is now DISABLED for {scope}: it is no longer evaluated, so the attacks \
                 it detects pass this WAF unrecorded.\n\
                 If the goal is to measure this rule's false positives rather than to remove it, \
                 use `--log-only` instead."
            ),
        ),
    };

    let row = db
        .upsert_rule_override(&waf_storage::models::CreateRuleOverride {
            rule_id: rule_id.to_owned(),
            host_code: host.map(str::to_owned),
            enabled,
            action_override,
            note,
        })
        .await?
        .ok_or_else(|| anyhow::anyhow!("host {scope} disappeared while writing the override"))?;

    println!("{outcome}");
    println!("Stored as override #{}.", row.id);
    println!("{RULE_OVERRIDE_RELOAD_NOTE}");
    Ok(())
}

/// The one fact every `sources` / `rules` failure message has to carry.
///
/// `[rules]` — `dir`, `sources`, `enable_builtin_*`, `hot_reload` — is read by
/// `rules validate` (which builds a [`RuleManager`] to parse one file) and by
/// `sources list` / the `rules update` refusal (which print `[[rules.sources]]`
/// back). Nothing else reads it: the daemon never constructs a `RuleManager`,
/// and the `rules` reads (`list` / `info` / `search` / `stats` / `export`) go to
/// the enforced set instead. Telling an operator to edit `[[rules.sources]]`
/// without saying so would trade one false promise for another.
const RULE_SOURCES_ARE_CLI_ONLY: &str = "Note: `[rules]` (dir / sources / builtin toggles) is consulted by `rules validate` and by \
     `sources list` only, and changes nothing about what is enforced. The running proxy compiles \
     its OWASP CRS set from `rules/owasp-crs/` at startup and takes every operator-managed rule \
     (hosts, IP/URL lists, custom Rhai rules, sensitive patterns, bot patterns) from the database.";

/// Why no `sources` / `rules` sub-command fetches a remote feed.
///
/// `sources update` / `sources sync` used to redirect to `rules update` as the
/// one that "really does fetch"; it fetched into a registry it then threw away,
/// and is now withheld outright. Three commands pointing at each other in a
/// circle is how an operator concludes the feature exists somewhere.
const NO_REMOTE_RULE_FETCH: &str = "No sub-command fetches a remote rule feed: `rules update` is withheld too. A feed URL is a \
     supply chain — whoever controls it controls what this WAF detects — and pinning, signature \
     verification and review-before-apply are not designed yet, so the fetch does not happen \
     rather than happening unchecked.";

// ── Bot commands ──────────────────────────────────────────────────────────────

/// What every mutating `bot` sub-command has to say.
///
/// The CLI writes to the database directly; a `prx-waf run` process already
/// serving traffic is holding its own compiled snapshot and will not notice.
/// Saying "added" without saying this is how an operator ends up believing a
/// rule is live when it is not.
const BOT_RELOAD_NOTE: &str = "A running proxy keeps its current snapshot until it reloads. \
     Apply it with `POST /api/reload` (Admin UI → any rule change triggers one) or restart the \
     process. Changes made through the Admin UI / `POST /api/bot-patterns` take effect \
     immediately and need none of this.";

/// Load the operator bot patterns into a detached [`BotCheck`], the way the
/// engine does at startup, so `bot list` / `bot test` report the *running*
/// semantics (precedence, whitelisting, skipped rows) and not a re-implementation.
async fn bot_checker_from_db(
    db: &waf_storage::Database,
) -> anyhow::Result<(BotCheck, Vec<waf_storage::models::BotPattern>)> {
    let rows = db.list_bot_patterns(false).await?;
    let patterns: Vec<UserBotPattern> = rows
        .iter()
        .filter(|r| r.enabled && r.pattern_type == "ua")
        .filter_map(|r| {
            BotAction::parse(&r.action).map(|action| UserBotPattern {
                id: r.id,
                name: r.name.clone(),
                pattern: r.pattern.clone(),
                action,
            })
        })
        .collect();
    let checker = BotCheck::new();
    checker.load_user_patterns(patterns);
    Ok((checker, rows))
}

async fn run_bot_cmd(cmd: BotCommands, config: &AppConfig) -> anyhow::Result<()> {
    let db = waf_storage::Database::connect(&config.storage.database_url, config.storage.max_connections).await?;

    match cmd {
        BotCommands::List => {
            let (_, rows) = bot_checker_from_db(&db).await?;

            println!("{:<16} {:<46} {:<8} {:<8} Pattern", "ID", "Name", "Action", "Source");
            println!("{}", "-".repeat(120));
            for r in BUILTIN_GOOD_BOTS.iter().chain(BUILTIN_BAD_BOTS) {
                println!(
                    "{:<16} {:<46} {:<8} {:<8} {}",
                    truncate(r.id, 15),
                    truncate(r.name, 45),
                    r.action.as_str(),
                    "builtin",
                    r.pattern,
                );
            }
            for r in &rows {
                let source = if r.enabled { "user" } else { "user-off" };
                println!(
                    "{:<16} {:<46} {:<8} {:<8} {}",
                    truncate(&waf_engine::user_rule_id(r.id), 15),
                    truncate(&r.name, 45),
                    truncate(&r.action, 7),
                    source,
                    r.pattern,
                );
            }
            println!();
            println!(
                "{} built-in signatures ({} allow, {} block), {} operator pattern(s) — {} enabled.",
                BUILTIN_GOOD_BOTS.len() + BUILTIN_BAD_BOTS.len(),
                BUILTIN_GOOD_BOTS.len(),
                BUILTIN_BAD_BOTS.len(),
                rows.len(),
                rows.iter().filter(|r| r.enabled).count(),
            );
        }

        BotCommands::Add {
            pattern,
            action,
            name,
            description,
        } => {
            // Compile before writing: the same check the admin API runs, so a
            // bad regex is a non-zero exit here rather than a row the engine
            // silently skips forever.
            if let Err(e) = validate_user_pattern(&pattern) {
                anyhow::bail!("pattern {pattern:?} was NOT added: {e}");
            }
            let parsed = BotAction::parse(&action).ok_or_else(|| {
                anyhow::anyhow!(
                    "pattern {pattern:?} was NOT added: unsupported action {action:?}. Only \
                     \"block\" and \"allow\" are implemented — detect-without-blocking is a \
                     per-host setting (log_only_mode), not a per-rule one, and there is no \
                     challenge/captcha subsystem."
                )
            })?;
            let enabled = db.count_enabled_bot_patterns().await?;
            if enabled >= i64::try_from(MAX_USER_PATTERNS).unwrap_or(i64::MAX) {
                anyhow::bail!(
                    "pattern {pattern:?} was NOT added: the operator set is full \
                     ({MAX_USER_PATTERNS} enabled patterns). Disable or remove one first."
                );
            }

            let name = name.unwrap_or_else(|| truncate(&pattern, 100));
            let row = db
                .create_bot_pattern(waf_storage::models::CreateBotPattern {
                    name,
                    pattern,
                    pattern_type: Some("ua".to_string()),
                    action: Some(parsed.as_str().to_string()),
                    description,
                    enabled: Some(true),
                })
                .await?;
            println!(
                "Added {} — {} ({}): {}",
                waf_engine::user_rule_id(row.id),
                row.name,
                row.action,
                row.pattern
            );
            println!("{BOT_RELOAD_NOTE}");
        }

        BotCommands::Remove { pattern } => {
            // Accept either the numeric row id (what `bot list` shows after the
            // `BOT-USER-` prefix) or the exact pattern text.
            let removed = if let Ok(id) = pattern.parse::<i32>() {
                u64::from(db.delete_bot_pattern(id).await?)
            } else {
                db.delete_bot_patterns_by_pattern(&pattern).await?
            };
            if removed == 0 {
                anyhow::bail!(
                    "no operator bot pattern matched {pattern:?} — nothing was removed.\n\
                     Give the numeric id from `prx-waf bot list` (the digits after `BOT-USER-`) or \
                     the exact pattern text. Built-in signatures are compiled into the binary and \
                     cannot be removed; add an `allow` pattern to whitelist a User-Agent they catch."
                );
            }
            println!("Removed {removed} operator bot pattern(s) matching {pattern:?}.");
            println!("{BOT_RELOAD_NOTE}");
        }

        BotCommands::Test { user_agent } => {
            let (checker, _) = bot_checker_from_db(&db).await?;
            let matches = checker.explain(&user_agent);
            if matches.is_empty() {
                println!("No bot rules matched: {user_agent}");
            } else {
                for m in &matches {
                    let source = if m.builtin { "builtin" } else { "user" };
                    println!("MATCH: {} — {} (action: {}, {source})", m.id, m.name, m.action.as_str());
                }
                // Precedence, not just membership — mirrors `BotCheck::check`.
                if let Some(first) = matches.first() {
                    let verdict = match first.action {
                        BotAction::Allow => "ALLOW (whitelisted; bot detection stops here)",
                        BotAction::Block => "BLOCK",
                    };
                    println!();
                    println!("Verdict: {verdict} — decided by {}", first.id);
                }
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
///
/// `taking_over` is the `run --upgrade` flag: this process is to receive the
/// listening sockets of a prx-waf already running on this host rather than bind
/// its own. See the `upgrade` module.
fn run_server(config: &AppConfig, taking_over: bool) -> anyhow::Result<()> {
    use pingora_core::server::Server;
    use pingora_core::server::configuration::Opt;

    // Settled before anything expensive happens. On a handover launch an
    // unusable socket directory is fatal, and discovering that after a database
    // pool is open and the rule set is loaded would leave a half-started
    // process racing the one it was meant to replace.
    let handover_sock = match upgrade::resolve(config.proxy.upgrade_sock.as_deref()) {
        Ok(sock) => Some(sock),
        Err(e) if taking_over => {
            return Err(e.context(
                "this process was started with `run --upgrade` to take the listening sockets over from a running \
                 prx-waf, and the socket that handover travels on cannot be placed. Nothing has been signalled, so \
                 the running process is still serving",
            ));
        }
        Err(e) => {
            tracing::warn!(
                "Graceful upgrade is UNAVAILABLE for this process: {e:#}. Startup and traffic filtering are \
                 UNAFFECTED, but a future `run --upgrade` will have nowhere to hand the listeners over, so a \
                 configuration or binary change will mean a restart that drops connections."
            );
            None
        }
    };

    // Resolved once, then both broadcast and handed to Pingora, so the line the
    // operator reads is the count the data plane is actually built with.
    let worker_threads = config.proxy.worker_thread_plan();

    // Metrics come up before anything else records, so that a counter can never
    // miss the first request. `init` allocates the whole table up front — the
    // size is a function of `max_host_labels`, not of traffic — and returns
    // `false` when the operator turned metrics off, in which case every record
    // site downstream stays a `OnceLock` load and a branch.
    let metrics_active = waf_common::metrics::init(&config.metrics);

    // Report the admin-API reachable surface before anything else binds, so
    // the very first thing an operator sees is whether the management API is
    // exposed and what to do about it.
    for line in admin_exposure_startup_broadcast(&config.api, &config.security)
        .into_iter()
        // Right after the bind-scope broadcast, because it is about the same
        // two settings: a `[::]` bind is what turns IPv4 clients into
        // IPv4-mapped addresses in the first place.
        .chain(ipv4_mapped_config_startup_broadcast(
            &config.proxy,
            &config.api,
            &config.http3,
            &config.security,
        ))
        // How many cores the data plane can actually use. Announced before the
        // listeners come up, because it is the one capacity figure an operator
        // cannot read back off a default config file.
        .chain(worker_thread_startup_broadcast(worker_threads))
        // Whether this process can be watched at all, and who can watch it.
        // Grouped with the other exposure lines because it is the same class of
        // question: a listener, its scope, and what reading it gets you.
        .chain(metrics_startup_broadcast(&config.metrics))
        // Whether this process can be replaced without dropping connections,
        // and on which path the replacement will reach it. Both halves of a
        // handover have to name the same socket, and this line is where an
        // operator reads back the one this process derived.
        .chain(handover_startup_broadcast(
            handover_sock.as_ref(),
            taking_over,
            config.proxy.drain_timeout_secs,
        ))
    {
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

    // Pingora carries the proxy listener across an upgrade, and nothing else.
    // The admin API, the metrics endpoint and the HTTP/3 listener each own a
    // socket on a runtime of their own, outside the file-descriptor table
    // Pingora hands over, and the process being replaced does not release those
    // ports until it exits — after the close timeout, the grace period and the
    // last in-flight request. An incoming process that binds them once would
    // therefore find every one of them taken, log three errors and come up with
    // no management plane at all, permanently, because the threads that failed
    // are gone by the time the ports free up. So on a handover launch, and only
    // then, each of the three keeps retrying for as long as the contention can
    // plausibly last.
    let handover_window = taking_over
        .then(|| upgrade::handover_bind_window(std::time::Duration::from_secs(config.proxy.drain_timeout_secs)));

    // What `[proxy] listen_addr_tls` will actually do on this launch. Resolved
    // here rather than beside the other startup broadcasts because the shipped
    // answer comes out of the database, which does not exist until `init_async`
    // has run; and before the HTTP/3 thread is spawned so its own certificate
    // line can be compared with this one in the log without scrolling.
    let tls_listener = rt.block_on(resolve_tls_listener(&config.proxy, &api_state.db));
    for line in tls_listener.startup_broadcast(&config.http3) {
        match line.level {
            BroadcastLevel::Info => info!("{}", line.text),
            BroadcastLevel::Warn => tracing::warn!("{}", line.text),
        }
    }

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
            let served = upgrade::serve_through_handover("Management API", handover_window, || {
                start_api_server(&api_listen, Arc::clone(&api_state_bg))
            })
            .await;
            if let Err(e) = served {
                tracing::error!("API server error: {}", e);
            }
        });
    });

    // The scrape endpoint gets its own thread and its own runtime for the same
    // reason the admin API does: neither may share the Pingora worker threads,
    // which exist to serve traffic. Its own *listener* rather than a route on
    // the admin API is a separate decision, argued in
    // `waf_api::metrics_endpoint`.
    //
    // A failure here is logged and dropped, never fatal. A metrics port that is
    // already in use must not stop a WAF from filtering traffic — losing
    // observability is bad, losing the firewall is worse — and the startup
    // broadcast above has already told the operator where to look.
    if metrics_active {
        let metrics_listen = config.metrics.listen_addr.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build metrics runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let served = upgrade::serve_through_handover("Metrics endpoint", handover_window, || {
                    waf_api::metrics_endpoint::serve(&metrics_listen)
                })
                .await;
                if let Err(e) = served {
                    // `{e:#}` so the context chain from `serve` — which stage
                    // failed, and the OS error under it — reaches the log. The
                    // rest of this line exists because the previous version
                    // printed only the cause: an operator who reads "address in
                    // use" still has to find out which knob moves the port, and
                    // whether their WAF is now down.
                    tracing::error!(
                        "Metrics endpoint is NOT serving on {metrics_listen}: {e:#}. Nothing can scrape this \
                         process; recording continues in memory and traffic filtering is UNAFFECTED, so this is \
                         not fatal. If the port is taken, find the holder with `ss -ltnp | grep {metrics_listen}` \
                         and move this listener with [metrics] listen_addr in the config file or \
                         PRXWAF_METRICS_LISTEN_ADDR in the environment; set [metrics] enabled = false to stop \
                         binding at all."
                    );
                }
            });
        });
    }

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
        // Same `[proxy.upstream_timeouts]` the Pingora path resolves below; the
        // H3 forwarder maps it onto reqwest (see `UpstreamTimeouts::apply_to_reqwest`).
        let h3_upstream_timeouts = gateway::UpstreamTimeouts::from_config(&config.proxy.upstream_timeouts);
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
                //
                // Retried through a handover for the same reason as the other
                // two listeners, with one caveat that no amount of retrying
                // fixes: this is a UDP socket, and QUIC connection state lives
                // in the process, not in the kernel. Even if the descriptor
                // were carried across, the incoming process could not decrypt
                // a connection the outgoing one negotiated. HTTP/3 clients are
                // dropped at the handover and reconnect; only HTTP/1.1 and
                // HTTP/2 over the Pingora listener survive it.
                let served = upgrade::serve_through_handover("HTTP/3 listener", handover_window, || {
                    gateway::http3::start_http3_server(
                        addr,
                        cert_pem.clone(),
                        key_pem.clone(),
                        h3_config.upstream_tls_verify,
                        h3_smuggling_detection,
                        Arc::clone(&h3_engine),
                        Arc::clone(&h3_router),
                        h3_upstream_timeouts,
                    )
                })
                .await;
                if let Err(e) = served {
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

    // Build and run Pingora proxy (blocks forever).
    //
    // The thread count is global to the server rather than set per service:
    // Pingora resolves each service's runtime as
    // `service.threads().unwrap_or(conf.threads)`
    // (`pingora-core-0.8.1/src/server/mod.rs:705`), so leaving every service's
    // own override at `None` keeps one lever for the whole data plane instead
    // of a per-listener count that has to be kept in sync.
    //
    // `Opt.upgrade` is the entire receiving half of the zero-downtime handover:
    // `Bootstrap::new` copies it (`bootstrap_services.rs:95`) and `load_fds`
    // reads the listening descriptors off the socket only when it is set
    // (`bootstrap_services.rs:172`). Passing `None` here, as this did, left the
    // outgoing process's SIGQUIT handler sending file descriptors that nothing
    // was ever going to collect.
    let mut server = Server::new_with_opt_and_conf(
        Opt {
            upgrade: taking_over,
            ..Opt::default()
        },
        proxy_server_conf(
            worker_threads.threads,
            handover_sock.as_ref(),
            config.proxy.drain_timeout_secs,
        )?,
    );
    if taking_over {
        info!(
            "Waiting up to {}s for the running prx-waf to hand over its listening sockets. If it does not, this \
             process exits and that one keeps serving.",
            upgrade::HANDOVER_SOCK_RETRIES
        );
    }
    // Blocks here on a handover launch, until the descriptors arrive or the
    // wait is exhausted — in which case Pingora exits the process itself
    // (`bootstrap_services.rs:158`), which is the outcome we want: no listener
    // was taken, and the process being replaced is untouched.
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

    // Upstream timeouts are unlimited unless configured, so the log stays quiet
    // on a default install and is unambiguous on a configured one: an operator
    // who set a bound can confirm from the log that it is armed and at what
    // value, without reading the config off the box.
    proxy.upstream_timeouts = gateway::UpstreamTimeouts::from_config(&config.proxy.upstream_timeouts);
    if !proxy.upstream_timeouts.is_unlimited() {
        info!(
            "Upstream timeouts armed: {} — connections exceeding a stage are cut",
            proxy.upstream_timeouts.summary()
        );
    }

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
    add_tls_endpoint(&mut proxy_service, &tls_listener);
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

/// What `[proxy] listen_addr_tls` resolved to on this launch.
///
/// Three states rather than an `Option`, because "no TLS listener" has two very
/// different causes and an operator who reads only the log must be able to tell
/// them apart: switched off deliberately, or asked for and not deliverable.
enum TlsListener {
    /// `[proxy] listen_addr_tls` is empty. Nothing was asked for.
    NotRequested,
    /// The address will be bound and this certificate served on it.
    Ready {
        addr: String,
        material: Box<gateway::tls_listener::TlsMaterial>,
    },
    /// The address was asked for and will not be bound.
    Unavailable { addr: String, reason: String },
}

impl TlsListener {
    /// Say, at every launch, exactly what this port is doing.
    ///
    /// `listen_addr_tls` has shipped with a default of `0.0.0.0:443` since long
    /// before anything listened on it, so silence here is indistinguishable
    /// from the bug this replaces. Every branch emits a line.
    fn startup_broadcast(&self, http3: &waf_common::config::Http3Config) -> Vec<BroadcastLine> {
        let mut lines = Vec::new();
        match self {
            Self::NotRequested => {
                lines.push(BroadcastLine::info(
                    "TLS termination is off: [proxy] listen_addr_tls is empty. Clients reach this WAF over plaintext \
                     HTTP only. Set it to an address (0.0.0.0:443 is the shipped default) and provision a certificate \
                     to serve HTTPS here."
                        .to_string(),
                ));
            }
            Self::Unavailable { addr, reason } => {
                lines.push(BroadcastLine::warn(format!(
                    "TLS termination is NOT active: [proxy] listen_addr_tls = {addr} was requested but nothing will \
                     bind it, so HTTPS clients get connection refused while the plaintext listener keeps serving. \
                     {reason}"
                )));
            }
            Self::Ready { addr, material } => {
                lines.push(BroadcastLine::info(format!(
                    "TLS termination active on {addr}, certificate from {}. TLS 1.2 and 1.3 only — Pingora's rustls \
                     backend builds the acceptor with exactly those two protocol versions and the ring provider's \
                     cipher suites, so 1.0/1.1, export and null suites cannot be negotiated. ALPN offers h2 and \
                     http/1.1.",
                    material.origin.describe()
                )));
                if !material.unserved_domains.is_empty() {
                    lines.push(BroadcastLine::warn(format!(
                        "One certificate serves this port and {} other active certificate(s) in the store will NOT be \
                         presented: {}. Pingora 0.8.1's rustls backend has one certificate per endpoint and no SNI \
                         callback, so clients asking for those names get a certificate-name mismatch. Cover them with \
                         one SAN or wildcard certificate, pin the right one with [proxy] tls_cert_pem / tls_key_pem, \
                         or terminate their TLS elsewhere.",
                        material.unserved_domains.len(),
                        material.unserved_domains.join(", ")
                    )));
                }
                // Renewal writes to the database and to nothing else. The
                // acceptor holds certificates rustls parsed once, at listener
                // construction (`listeners/tls/rustls/mod.rs:49-83`), and
                // Pingora exposes no way to replace them on a running endpoint.
                if matches!(material.origin, gateway::tls_listener::CertOrigin::AcmeStore { .. }) {
                    lines.push(BroadcastLine::info(
                        "This certificate was read once, at startup. ACME renewal updates the certificates table but \
                         cannot reach the running listener — Pingora's rustls acceptor parses its certificate when \
                         the endpoint is built and offers no way to swap it afterwards — so a renewed certificate is \
                         served only after a restart. `prx-waf run --upgrade` does that without dropping connections."
                            .to_string(),
                    ));
                }
                if http3.enabled && material.origin == gateway::tls_listener::CertOrigin::ConfiguredFiles {
                    lines.push(BroadcastLine::info(
                        "HTTP/3 reads [http3] cert_pem / key_pem and this listener reads [proxy] tls_cert_pem / \
                         tls_key_pem. Point both pairs at the same files unless the two protocols are meant to \
                         present different certificates."
                            .to_string(),
                    ));
                } else if http3.enabled {
                    lines.push(BroadcastLine::warn(
                        "HTTP/3 is enabled and the two TLS listeners have different certificate sources: this one \
                         serves the certificates table, HTTP/3 serves the files named in [http3] cert_pem / key_pem \
                         and never reads the database. A client that negotiates h3 over the Alt-Svc advertisement can \
                         therefore be shown a different certificate from the one it got over TCP. Set [proxy] \
                         tls_cert_pem / tls_key_pem to the same files [http3] uses to make the two agree."
                            .to_string(),
                    ));
                }
            }
        }
        lines
    }
}

/// Decide what `[proxy] listen_addr_tls` does on this launch.
async fn resolve_tls_listener(proxy: &waf_common::config::ProxyConfig, db: &Database) -> TlsListener {
    let addr = proxy.listen_addr_tls.trim();
    if addr.is_empty() {
        return TlsListener::NotRequested;
    }
    let addr = addr.to_string();

    // A malformed address is caught before the certificate work rather than
    // after it, so the operator is told about the typo instead of about a
    // certificate that was never the problem.
    if addr.parse::<std::net::SocketAddr>().is_err() {
        return TlsListener::Unavailable {
            reason: format!("{addr:?} does not parse as an address:port."),
            addr,
        };
    }

    let plan = gateway::tls_listener::resolve(
        proxy.tls_cert_pem.as_deref(),
        proxy.tls_key_pem.as_deref(),
        db,
        upgrade::private_tls_dir,
    )
    .await;

    match plan {
        gateway::tls_listener::TlsPlan::Ready(material) => TlsListener::Ready { addr, material },
        gateway::tls_listener::TlsPlan::Unavailable { reason } => TlsListener::Unavailable { addr, reason },
    }
}

/// Attach the TLS endpoint to the proxy service, when there is one to attach.
///
/// `enable_h2` sets the ALPN to prefer h2 with http/1.1 allowed, which is what
/// a browser expects of an HTTPS origin; the plaintext listener is untouched
/// and stays HTTP/1.1. The certificate and key have already been parsed and
/// paired by `gateway::tls_listener::validate`, which is what keeps the
/// `panic!`/`unwrap` inside Pingora's own `TlsSettings::build` out of reach.
fn add_tls_endpoint<SV>(service: &mut pingora_core::services::listening::Service<SV>, listener: &TlsListener) {
    let TlsListener::Ready { addr, material } = listener else {
        return;
    };
    let (cert, key) = (material.cert_path.display(), material.key_path.display());
    match pingora_core::listeners::tls::TlsSettings::intermediate(&cert.to_string(), &key.to_string()) {
        Ok(mut settings) => {
            settings.enable_h2();
            service.add_tls_with_settings(addr, None, settings);
        }
        // Unreachable with the rustls backend, whose `intermediate` only ever
        // returns Ok. Reported rather than ignored so that swapping the backend
        // cannot turn TLS off in silence.
        Err(e) => tracing::error!(
            "TLS listener on {addr} could not be created from {cert} / {key}: {e}. The plaintext listener is unaffected."
        ),
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

/// Announce whether this process can be replaced without dropping connections.
///
/// Worth a startup line for the same reason the worker count is: it is a
/// property of the running process that appears in no config file on a default
/// install. Both halves of a handover have to name the same socket, and the
/// derived path is a function of the effective uid, so printing it is how an
/// operator confirms from the outgoing process's log what the incoming one will
/// look for.
fn handover_startup_broadcast(
    sock: Option<&upgrade::UpgradeSock>,
    taking_over: bool,
    drain_secs: u64,
) -> Vec<BroadcastLine> {
    // Said whether or not a handover is possible, because it is also the cost
    // of an ordinary `systemctl stop`, and because the value it replaces was
    // Pingora's unconditional five minutes.
    let drain = BroadcastLine::info(format!(
        "Stop drain: {drain_secs}s — after SIGTERM, or after handing its listeners to a replacement, this process \
         keeps serving already-accepted requests for {drain_secs}s and then gives its runtimes 5s more before \
         cutting them. It is a fixed wait, not a drain detector: the full {drain_secs}s is spent even when nothing \
         is in flight, so it is the cost of every stop. Set [proxy] drain_timeout_secs (or \
         PRXWAF_DRAIN_TIMEOUT_SECS) above the longest request this proxy should be allowed to finish, and below \
         your supervisor's kill timeout."
    ));

    let Some(sock) = sock else {
        // The refusal was already logged in full, with its reason, where it was
        // decided; repeating it here would only say it twice.
        return vec![drain];
    };
    let path = sock.path.display();
    let origin = match sock.source {
        upgrade::SockSource::Configured => "set by [proxy] upgrade_sock / PRXWAF_UPGRADE_SOCK",
        upgrade::SockSource::SystemRuntime => "derived — the system runtime directory, which this process owns",
        upgrade::SockSource::UserTemp => "derived — a private per-uid directory, this process not being root",
    };

    if taking_over {
        return vec![
            BroadcastLine::info(format!(
                "Graceful upgrade: this process is TAKING OVER. It will wait on {path} ({origin}) for the running \
                 prx-waf to hand its listening sockets across. Send that process SIGQUIT now. Until then this \
                 process holds no listener, and if it gives up waiting it exits without having disturbed anything."
            )),
            drain,
        ];
    }

    vec![
        BroadcastLine::info(format!(
            "Graceful upgrade: available on {path} ({origin}). To change the configuration or the binary without \
             dropping connections, start the new process with `prx-waf run --upgrade` FIRST and only then send this \
             one SIGQUIT. Sending SIGQUIT with no process waiting on that socket is a shutdown, not an upgrade: this \
             process will spend its retry budget looking for a successor that is not there and then exit, leaving \
             the port unserved."
        )),
        drain,
    ]
}

/// Build the Pingora server configuration the proxy data plane runs under.
///
/// This exists so the worker-thread count has somewhere to be written. The
/// previous `Server::new(None)` silently took `ServerConf::default()`, whose
/// `threads: 1` (`pingora-core-0.8.1/src/server/configuration/mod.rs:137`) is
/// what pinned the whole data plane to one core regardless of the machine.
/// `ServerConf::new()` is the same conf `Server::new(None)` would have built,
/// so nothing else about the server changes.
///
/// `handover_sock` is the second thing written here. Pingora reads the socket
/// path off this conf on both sides of an upgrade — the outgoing process at
/// `server/mod.rs:283`, the incoming one at `bootstrap_services.rs:98` — so
/// leaving it at the shipped `/tmp/pingora_upgrade.sock` would have put the
/// handover in a world-writable directory. `None` leaves the default in place
/// but nothing ever asks for the handover, since the flag that arms the
/// receiving side is refused in the same breath.
/// `drain_secs` is the third. Left unset, Pingora sleeps its own
/// `EXIT_TIMEOUT` — 300 seconds (`server/mod.rs:56`, applied at `:775`) — after
/// every graceful stop, unconditionally, whether or not a single connection is
/// still open. That is five minutes of two live processes holding two database
/// pools and two sets of management ports after a handover whose data plane
/// finished in two seconds, and five minutes of a `systemctl stop` that
/// systemd will `SIGKILL` at ninety.
fn proxy_server_conf(
    threads: usize,
    handover_sock: Option<&upgrade::UpgradeSock>,
    drain_secs: u64,
) -> anyhow::Result<pingora_core::server::configuration::ServerConf> {
    use pingora_core::server::configuration::ServerConf;

    let mut conf =
        ServerConf::new().ok_or_else(|| anyhow::anyhow!("failed to build the default Pingora server configuration"))?;
    conf.threads = threads;
    conf.grace_period_seconds = Some(drain_secs);
    if let Some(sock) = handover_sock {
        conf.upgrade_sock = sock.path.to_string_lossy().into_owned();
        conf.upgrade_sock_connect_accept_max_retries = Some(upgrade::HANDOVER_SOCK_RETRIES);
    }
    Ok(conf)
}

/// Report how many threads the proxy data plane will run on, and why.
///
/// Worth a startup line because the count is invisible from anywhere else: it
/// is not in the config file on a default install (the key is optional and the
/// default is derived), `ps` shows a thread count that has never matched it —
/// the process holds background-worker threads for the API, HTTP/3, the cluster
/// and the storage pool — and the number an operator actually needs is "how
/// many cores can serve traffic", which only this decision answers.
///
/// Takes the resolved plan rather than the config so it reports the same
/// decision the server is actually built with, not a second resolution of it.
fn worker_thread_startup_broadcast(plan: WorkerThreadPlan) -> Vec<BroadcastLine> {
    let detected = plan.available_cpus.map_or_else(
        || "the CPUs available to this process could not be detected".to_string(),
        |cpus| format!("{cpus} CPU(s) available to this process"),
    );
    // Said once, wherever the count came from: the detected number is an
    // affinity/quota number, and an operator comparing it against `nproc` on
    // the host will otherwise read a correct value as a bug.
    let caveat = "The detected figure comes from std::thread::available_parallelism, which honours the cgroup CPU \
                  quota and this process's CPU affinity mask — in a container it is the quota, not the host's core \
                  count, and under taskset it is the pinned set.";

    let text = match plan.source {
        WorkerThreadSource::DefaultFollowsCpus => format!(
            "Proxy worker threads: {} — [proxy] worker_threads is unset, so the data plane follows the CPUs it may \
             run on ({detected}). {caveat} Set [proxy] worker_threads = N (or PRXWAF_WORKER_THREADS=N) to fix the \
             count.",
            plan.threads
        ),
        WorkerThreadSource::ExplicitFollowsCpus => format!(
            "Proxy worker threads: {} — [proxy] worker_threads = 0 means follow the CPUs this process may run on \
             ({detected}). {caveat}",
            plan.threads
        ),
        WorkerThreadSource::Fixed => format!(
            "Proxy worker threads: {} — fixed by [proxy] worker_threads ({detected}). {caveat}",
            plan.threads
        ),
    };

    // One thread on a host that offered more is the throughput ceiling this
    // key exists to lift: the data plane cannot exceed one core no matter how
    // many the machine has, so it is stated as a warning rather than buried in
    // an informational line.
    if plan.is_single_threaded_on_a_wider_host() {
        let remedy = match plan.source {
            WorkerThreadSource::Fixed => "Raise [proxy] worker_threads, or set it to 0 to follow the available CPUs.",
            _ => "Set [proxy] worker_threads = N explicitly to pick a count without relying on detection.",
        };
        vec![BroadcastLine::warn(format!(
            "{text} THROUGHPUT CEILING: the proxy data plane is running on a single thread, so it cannot use more \
             than one core however many this machine has, and adding cores will not add throughput. {remedy}"
        ))]
    } else {
        vec![BroadcastLine::info(text)]
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

/// Build the metrics-endpoint startup broadcast.
///
/// Reuses [`classify_admin_bind_scope`] deliberately: the exposure question is
/// the same question the admin API answers, and a second classifier would be a
/// second place for "is this loopback" to be got wrong. What differs is the
/// consequence. The scrape endpoint carries **no credential at all** — see
/// `waf_api::metrics_endpoint` for why adding one is worse than not having one
/// — so its bind address is its entire access control, and a non-loopback bind
/// is stated as a warning rather than as information.
///
/// What leaks if it is reachable is worth naming rather than implying: per-host
/// request volume, block rate and detection counts by phase. That is a map of
/// which sites this WAF fronts, how busy each is, and which attacks against them
/// are currently getting through.
fn metrics_startup_broadcast(metrics: &MetricsConfig) -> Vec<BroadcastLine> {
    if !metrics.enabled {
        return vec![BroadcastLine::warn(
            "Metrics DISABLED ([metrics] enabled = false): no /metrics endpoint is bound and nothing is recorded. \
             This process is unobservable — request rate, block rate, detection mix, per-lane cost and every \
             budget/degradation counter in docs/dos-budget.md are unavailable to a scraper, and the only remaining \
             signal is the log. Set [metrics] enabled = true (or PRXWAF_METRICS_ENABLED=1) to restore it.",
        )];
    }

    let addr = &metrics.listen_addr;
    let hosts = metrics.effective_max_hosts();
    let clamped = if hosts == metrics.max_host_labels {
        String::new()
    } else {
        format!(
            " ([metrics] max_host_labels = {} was clamped to the {hosts} ceiling.)",
            metrics.max_host_labels
        )
    };
    let cardinality = format!(
        "Cardinality is bounded: at most {hosts} distinct host label values plus one __other__ fold, so the series \
         count is a property of this setting and not of the traffic.{clamped}"
    );

    let Some(scope) = classify_admin_bind_scope(addr) else {
        return vec![BroadcastLine::warn(format!(
            "Metrics exposure UNKNOWN: [metrics] listen_addr={addr:?} does not parse as host:port, so its bind scope \
             cannot be assessed here and the listener will fail to bind. Metrics are still being recorded; nothing \
             can scrape them. {cardinality}"
        ))];
    };

    match scope {
        AdminBindScope::Loopback => vec![BroadcastLine::info(format!(
            "Metrics endpoint: http://{addr}/metrics is loopback-only — reachable only from processes on this host \
             (this container, if containerized). The endpoint is unauthenticated by design, so this bind is what \
             protects it; scrape it via a node-local Prometheus agent, or publish the port deliberately. {cardinality}"
        ))],
        AdminBindScope::Interface => vec![BroadcastLine::warn(format!(
            "Metrics exposure: [metrics] listen_addr={addr} binds a non-loopback interface and the endpoint is \
             UNAUTHENTICATED — every host that can route to that network can read per-host request volume, block \
             rate and detection counts by phase, which is a map of the sites this WAF fronts and which attacks \
             against them are landing. Restrict it at the firewall, or bind 127.0.0.1 and let a local agent forward \
             it. {cardinality}"
        ))],
        AdminBindScope::WildcardV4 | AdminBindScope::WildcardV6 => {
            let scope_desc = if scope == AdminBindScope::WildcardV4 {
                "every IPv4 interface of this host/container"
            } else {
                "every interface of this host/container (IPv4 and IPv6 alike on most kernels)"
            };
            vec![BroadcastLine::warn(format!(
                "Metrics exposure: CRITICAL — [metrics] listen_addr={addr} binds {scope_desc} and the endpoint is \
                 UNAUTHENTICATED, so ANY host that can reach this port can read per-host request volume, block rate \
                 and detection counts by phase. Bind 127.0.0.1 (the default) and scrape from a node-local agent, or \
                 put the port behind a firewall you control. {cardinality}"
            ))]
        }
    }
}

/// Report configuration that the IPv4-mapped-address normalization changed the
/// meaning of.
///
/// # What changed
///
/// A listener bound to the IPv6 wildcard `[::]` accepts IPv4 connections too
/// (Linux `net.ipv6.bindv6only=0`) and reports their peer address in
/// IPv4-mapped form, `::ffff:a.b.c.d`. That form used to travel unfolded all the
/// way to every IP decision, where it matched nothing: blocklists, threat feeds
/// and `CrowdSec` failed **open** (a banned IPv4 client got in), while the admin
/// allowlist, `trusted_proxies` and `GeoIP` `AllowOnly` failed **closed** (a
/// legitimate one was refused). Client addresses are now folded to plain IPv4 at
/// ingress, which fixes both — and, as a breaking consequence, retires every
/// config entry an operator wrote in mapped form to work around the old
/// fail-closed half.
///
/// # What this broadcast does
///
/// Names those entries, per list, with the plain-IPv4 spelling to replace them
/// with. Nothing is rewritten automatically: an IP allowlist is a perimeter, and
/// editing one on the operator's behalf during startup is not a decision this
/// process gets to make silently.
///
/// Only config-file lists can be checked here. Blocklist entries stored in the
/// database are checked as they load, by
/// `waf_engine::rules::IpRuleSet::{load, insert}`; addresses arriving from
/// `CrowdSec` LAPI, threat-intel feeds, cluster peers or existing
/// `security_events` rows are outside both and are covered in the release note.
fn ipv4_mapped_config_startup_broadcast(
    proxy: &waf_common::config::ProxyConfig,
    api: &ApiConfig,
    http3: &waf_common::config::Http3Config,
    security: &SecurityConfig,
) -> Vec<BroadcastLine> {
    use waf_common::net::ipv4_mapped_entries;

    let mut lines = Vec::new();

    for (setting, entries) in [
        ("[security] admin_ip_allowlist", &security.admin_ip_allowlist),
        ("[proxy] trusted_proxies", &proxy.trusted_proxies),
    ] {
        let offenders = ipv4_mapped_entries(entries);
        if !offenders.is_empty() {
            lines.push(BroadcastLine::warn(format!(
                "IPv4-mapped entries in {setting} are now DEAD and will never match: {}. Client addresses are normalized to plain IPv4 before every IP decision, so the `::ffff:` spelling — which used to be the only one that worked on a \"[::]\" listener — no longer matches anything. Rewrite each entry to the plain-IPv4 form shown in parentheses. Nothing was changed automatically.",
                offenders.join("; ")
            )));
        }
    }

    // Only relevant when a listener can actually produce mapped addresses.
    let v6_wildcard = |addr: &str| {
        addr.parse::<std::net::SocketAddr>()
            .is_ok_and(|s| s.ip().is_unspecified() && s.ip().is_ipv6())
    };
    let mut v6_listeners: Vec<&str> = Vec::new();
    for (setting, addr) in [
        ("[proxy] listen_addr", proxy.listen_addr.as_str()),
        ("[proxy] listen_addr_tls", proxy.listen_addr_tls.as_str()),
        ("[api] listen_addr", api.listen_addr.as_str()),
    ] {
        if v6_wildcard(addr) {
            v6_listeners.push(setting);
        }
    }
    if http3.enabled && v6_wildcard(&http3.listen_addr) {
        v6_listeners.push("[http3] listen_addr");
    }

    if !v6_listeners.is_empty() {
        lines.push(BroadcastLine::info(format!(
            "IPv6 wildcard bind on {}: IPv4 clients reach these listeners as IPv4-mapped addresses (::ffff:a.b.c.d) and are normalized to plain IPv4 before IP blocklists, threat feeds, CrowdSec, the admin allowlist, trusted_proxies and GeoIP see them. Write every IP/CIDR rule in plain IPv4 form; genuine IPv6 clients are matched as IPv6 and are unaffected. Upgrading from a release before this normalization existed: any rule you wrote as \"::ffff:x.x.x.x\" to work around the previous behaviour must be rewritten, and historical client_ip values already stored in the database keep whichever form they were recorded with.",
            v6_listeners.join(", ")
        )));
    }

    lines
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

/// Build the `CrowdSec` bouncer startup broadcast.
///
/// The operator-facing question at boot is: **where do this process's `CrowdSec`
/// decisions come from right now, and is anything being enforced yet?** The
/// bouncer's decision cache is in-memory and starts empty, and the first LAPI
/// pull happens on a background task *after* the proxy starts serving — so
/// between process start and that pull, the only thing standing between a known
/// bad IP and the origin is what was restored from the durable
/// `crowdsec_decisions` mirror. These lines say exactly how many that is.
///
/// Every state where the cache starts empty is a WARN, because every one of them
/// is a fail-open window: the bouncer matches no IP at all, so previously banned
/// clients are allowed through until a pull succeeds. The pull's own outcome
/// cannot be reported here (it has not happened yet); the sync task logs it at
/// `error!` when it fails with an empty cache.
fn crowdsec_startup_broadcast(
    config: &waf_engine::CrowdSecConfig,
    persist_enabled: bool,
    restore: &waf_engine::RestoreOutcome,
) -> Vec<BroadcastLine> {
    use waf_engine::crowdsec::config::{CrowdSecMode, FallbackAction};

    if config.mode == CrowdSecMode::Appsec {
        return vec![BroadcastLine::info(
            "CrowdSec mode=appsec: the local decision cache is not consulted on the request path, so the decision mirror is \
             not used, and crowdsec.fallback_action (which governs the bouncer) does not apply. Every request is judged by \
             the AppSec engine instead, under its own appsec_failure_action.",
        )];
    }

    let mut lines = crowdsec_mirror_broadcast(config, persist_enabled, restore);

    // What this node does when the bouncer has no decision set at all. `allow`
    // (the default) is the historical behaviour and needs no announcement; the
    // other two change what a request gets during a LAPI outage, and `block`
    // turns an outage into a total refusal of service — an operator must not
    // discover that from a pager.
    match config.fallback_action {
        FallbackAction::Allow => {}
        FallbackAction::Block => lines.push(BroadcastLine::warn(format!(
            "CrowdSec fallback_action=BLOCK (fail closed): whenever the LAPI bouncer has an EMPTY decision cache — LAPI at \
             {} unreachable and nothing restored from the local mirror — this WAF REFUSES EVERY REQUEST with 403 until a \
             pull succeeds, so a LAPI outage becomes a full outage of every site behind this node. A cache that is merely \
             stale (a pull failed but decisions are still cached) does NOT trigger it. Set fallback_action=\"allow\" to \
             fail open instead, or \"log\" to record the window without blocking.",
            config.lapi_url
        ))),
        FallbackAction::Log => lines.push(BroadcastLine::info(format!(
            "CrowdSec fallback_action=LOG: requests are still allowed while the LAPI bouncer has an EMPTY decision cache \
             (LAPI at {} unreachable and nothing restored from the local mirror), but each one records a \
             crowdsec:lapi-unavailable security event so the fail-open window is visible in the event log — one event per \
             request for as long as the outage lasts.",
            config.lapi_url
        ))),
    }

    lines
}

/// The decision-mirror half of [`crowdsec_startup_broadcast`]: where this
/// process's decisions came from and whether anything is enforced yet.
fn crowdsec_mirror_broadcast(
    config: &waf_engine::CrowdSecConfig,
    persist_enabled: bool,
    restore: &waf_engine::RestoreOutcome,
) -> Vec<BroadcastLine> {
    let first_pull_note = format!(
        "The first LAPI pull runs on a background task after the proxy starts serving and is retried every {}s until it \
         succeeds; a failure with an empty cache is logged at ERROR.",
        config.update_frequency_secs.max(5)
    );

    if !persist_enabled {
        return vec![BroadcastLine::warn(format!(
            "CrowdSec decision mirror DISABLED (crowdsec.persist_decisions=false): the bouncer starts with an EMPTY \
             decision cache, so until the first LAPI pull at {} succeeds it matches no IP and every previously banned \
             client is allowed through. {first_pull_note} Set crowdsec.persist_decisions=true to restore known decisions \
             from the local database at startup instead.",
            config.lapi_url
        ))];
    }

    if let Some(ref error) = restore.error {
        return vec![BroadcastLine::warn(format!(
            "CrowdSec decision mirror UNREADABLE ({error}): the bouncer starts with an EMPTY decision cache, so until the \
             first LAPI pull at {} succeeds it matches no IP and every previously banned client is allowed through. \
             {first_pull_note}",
            config.lapi_url
        ))];
    }

    if restore.restored == 0 {
        return vec![BroadcastLine::warn(format!(
            "CrowdSec decision mirror is EMPTY (0 unexpired rows in crowdsec_decisions; skipped {} expired, {} filtered \
             out by the configured scenario filters). Normal on a first run, otherwise it means nothing was mirrored. The \
             bouncer starts with an empty decision cache and matches no IP until the first LAPI pull at {} succeeds. \
             {first_pull_note}",
            restore.skipped_expired, restore.skipped_filtered, config.lapi_url
        ))];
    }

    vec![
        BroadcastLine::info(format!(
            "CrowdSec decision cache RESTORED from the local mirror: {} decisions enforced from the very first request, \
             before any LAPI contact (skipped {} already expired, {} filtered out by the configured scenario filters). \
             This is what closes the restart fail-open window when LAPI is unreachable at boot.",
            restore.restored, restore.skipped_expired, restore.skipped_filtered
        )),
        BroadcastLine::info(format!(
            "CrowdSec restored decisions are provisional until confirmed: the first successful FULL pull from {} replaces \
             the mirror wholesale and evicts every restored entry it does not confirm, so a ban lifted while this process \
             was down survives at most until then. {first_pull_note}",
            config.lapi_url
        )),
    ]
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
    /// Keeps the notification event producers and dispatcher alive while the
    /// server runs. Dropping it stops them.
    _notify: Option<NotifyRuntime>,
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

    // Pool occupancy has no record site — it is a level, not an event — so it
    // needs a clock. Started here rather than lazily: the question it answers
    // ("is the write path bottlenecked on connections?") is one an operator asks
    // during an incident, and a gauge that only starts on demand is not there
    // when the incident is. The task holds a `Weak` and exits when the pool
    // does, so the handle is deliberately dropped.
    drop(db.spawn_pool_gauge_sampler());

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
            // Absent → None → `upstream_uses_tls()` falls back to `ssl`, the
            // behaviour of every config file written before the key existed.
            upstream_ssl: entry.upstream_ssl,
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
            // Administrative on/off from the config file (defaults to serving).
            // Without this line the `..HostConfig::default()` below would force
            // `start_status = true` and a config-file `start_status = false`
            // would be a no-op — the site would keep serving while the operator
            // believed they had closed it.
            start_status: entry.start_status,
            // Custom block page from the config file. `None` keeps the built-in
            // template, which is what every config file has rendered so far.
            block_page_template: entry.block_page_template.clone(),
            ..HostConfig::default()
        });
        router.register(&cfg);
    }

    info!("Registered {} host routes", router.len());

    // Name every host whose upstream is encrypted only because `ssl = true` and
    // nobody said otherwise. `ssl` answers "is the site TLS" (it is what ACME
    // issues against, below) and used to answer "is the origin TLS" as well, so
    // the overwhelmingly common shape — public HTTPS in front, plaintext
    // 127.0.0.1 behind — dialled the origin over TLS and got a 502 with nothing
    // in the log connecting the two. The fallback stays, because removing it
    // would silently downgrade a genuinely encrypted origin connection to
    // cleartext. This makes the ambiguity loud instead, once, at startup.
    for host in router.list() {
        if host.upstream_tls_is_inferred_from_site_tls() {
            tracing::warn!(
                "Host {}:{} has ssl = true and no upstream_ssl, so its upstream {}:{} is dialled over \
                 TLS. `ssl` states that the SITE is TLS (it is what ACME issues for); if the origin \
                 speaks plaintext this connection fails with 502. Set upstream_ssl explicitly — false \
                 for a plaintext origin, true to keep TLS and silence this.",
                host.host,
                host.port,
                host.remote_host,
                host.remote_port,
            );
        }
    }

    // Build a load balancer for every host that declares a multi-backend pool.
    // Hosts without `backends` are absent from the registry and continue to use
    // their single `remote_host`/`remote_port` upstream (backward compatible).
    let lb_registry = Arc::new(LoadBalancerRegistry::new());
    // The same `Arc`s are handed to the notification runtime so `backend_down`
    // alerts observe the health flags this checker maintains, instead of opening
    // a second set of probes against the operator's upstreams.
    let mut monitored_pools: Vec<MonitoredPool> = Vec::new();
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
        monitored_pools.push(MonitoredPool {
            host_code: host.code.clone(),
            lb: Arc::clone(&lb),
        });
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

        // The durable decision mirror (`crowdsec_decisions`). Supplied here so
        // `init_crowdsec` can repopulate the bouncer cache from it *before*
        // returning; see `crowdsec_startup_broadcast` for what the operator is
        // told about the result.
        let decision_store: Option<Arc<dyn waf_engine::DecisionStore>> = if config.crowdsec.persist_decisions {
            Some(Arc::clone(&db) as Arc<dyn waf_engine::DecisionStore>)
        } else {
            None
        };

        if let Some(components) = init_crowdsec(cs_config.clone(), decision_store, shutdown_rx).await {
            info!(
                lapi_url = %cs_config.lapi_url,
                "CrowdSec integration active"
            );

            for line in crowdsec_startup_broadcast(&cs_config, config.crowdsec.persist_decisions, &components.restore) {
                match line.level {
                    BroadcastLevel::Info => info!("{}", line.text),
                    BroadcastLevel::Warn => tracing::warn!("{}", line.text),
                }
            }

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

    // `ShutdownGuards` is assembled at the end of this function: the notification
    // guard needs the shared `api_state`, which is only built below.

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

    let api_state = Arc::new(api_state);

    // Notification delivery. Until this call the admin UI could configure alert
    // channels and successfully "test send" them, but no real event ever reached
    // `dispatch_notification` — the channels were connected to nothing. Starting
    // the runtime installs the bus on the database (so blocked requests raise
    // `attack_detected` from the existing security-event write path) and spawns
    // the certificate-expiry and backend-health producers.
    let notify_guard = waf_api::notify_runtime::start(&config.notifications, &api_state, &db, monitored_pools);

    let guards = ShutdownGuards {
        _crowdsec: crowdsec_shutdown_guard,
        _community: community_shutdown_guard,
        _retention: retention_shutdown_guard,
        _notify: notify_guard,
    };

    Ok((
        engine,
        router,
        api_state,
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

    // ── Metrics exposure broadcast ───────────────────────────────────────────

    fn metrics_cfg(listen: &str) -> MetricsConfig {
        MetricsConfig {
            listen_addr: listen.to_string(),
            ..MetricsConfig::default()
        }
    }

    /// The shipped default has to be the quiet one. If the factory config warns,
    /// operators learn to ignore the warning.
    ///
    /// The port is pinned here as well as in `MetricsConfig::default`, because
    /// it is not a free choice: 9090 is Prometheus's own listen port and 9091 is
    /// pushgateway, so either would collide with the node-local scraper this
    /// default exists to be scraped by.
    #[test]
    fn shipped_metrics_bind_is_loopback_and_informational() {
        let cfg = MetricsConfig::default();
        assert_eq!(cfg.listen_addr, "127.0.0.1:9127");
        assert!(cfg.enabled, "metrics must ship on");
        let lines = metrics_startup_broadcast(&cfg);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Info, "{}", l.text);
        assert!(l.text.contains("loopback-only"), "{}", l.text);
    }

    /// The endpoint carries no credential, so a non-loopback bind is the whole
    /// exposure. It must warn, and it must say what reading it gets you.
    #[test]
    fn non_loopback_metrics_bind_warns_and_names_what_leaks() {
        for addr in ["0.0.0.0:9127", "[::]:9127", "192.0.2.10:9127"] {
            let lines = metrics_startup_broadcast(&metrics_cfg(addr));
            let l = lines.first().expect("broadcast is never empty");
            assert_eq!(l.level, BroadcastLevel::Warn, "{addr}: {}", l.text);
            assert!(l.text.contains("UNAUTHENTICATED"), "{addr}: {}", l.text);
            assert!(l.text.contains("block rate"), "{addr}: {}", l.text);
        }
    }

    /// Turning metrics off is a legitimate choice, but it is a choice with a
    /// consequence, and the log is the only place left to state it.
    #[test]
    fn disabled_metrics_say_the_process_is_unobservable() {
        let cfg = MetricsConfig {
            enabled: false,
            ..MetricsConfig::default()
        };
        let lines = metrics_startup_broadcast(&cfg);
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(l.text.contains("unobservable"), "{}", l.text);
    }

    /// A clamped `max_host_labels` must be reported, otherwise an operator who
    /// asked for a million host labels believes they got them.
    #[test]
    fn clamped_host_label_bound_is_reported() {
        let cfg = MetricsConfig {
            max_host_labels: 1_000_000,
            ..MetricsConfig::default()
        };
        let lines = metrics_startup_broadcast(&cfg);
        let text = &lines.first().expect("broadcast is never empty").text;
        assert!(text.contains("was clamped"), "{text}");
        assert!(
            text.contains(&waf_common::metrics::MAX_HOST_LABELS_CEILING.to_string()),
            "{text}"
        );
    }

    #[test]
    fn unparseable_metrics_addr_warns_rather_than_assuming() {
        let lines = metrics_startup_broadcast(&metrics_cfg("not-an-addr"));
        let l = lines.first().expect("broadcast is never empty");
        assert_eq!(l.level, BroadcastLevel::Warn, "{}", l.text);
        assert!(l.text.contains("UNKNOWN"), "{}", l.text);
    }

    /// The shipped TOML and the struct default must agree. They are two
    /// separate sources of the same decision, and a drift between them means
    /// the documented default is not the one a config-less install gets.
    #[test]
    fn shipped_toml_metrics_section_matches_the_struct_default() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/default.toml");
        let shipped = load_config(path).expect("shipped default.toml must load").metrics;
        assert_eq!(shipped, MetricsConfig::default());
    }

    // ── IPv4-mapped config broadcast ─────────────────────────────────────────

    fn proxy_cfg(listen: &str, trusted: &[&str]) -> waf_common::config::ProxyConfig {
        waf_common::config::ProxyConfig {
            listen_addr: listen.to_string(),
            trusted_proxies: trusted.iter().map(|s| (*s).to_string()).collect(),
            ..waf_common::config::ProxyConfig::default()
        }
    }

    fn http3_off() -> waf_common::config::Http3Config {
        waf_common::config::Http3Config {
            enabled: false,
            ..waf_common::config::Http3Config::default()
        }
    }

    fn mapped_broadcast(
        proxy: &waf_common::config::ProxyConfig,
        api: &ApiConfig,
        security: &SecurityConfig,
    ) -> Vec<BroadcastLine> {
        ipv4_mapped_config_startup_broadcast(proxy, api, &http3_off(), security)
    }

    /// The shipped defaults are IPv4-only with empty lists: nothing to say.
    #[test]
    fn ipv4_only_defaults_say_nothing_about_mapping() {
        let lines = mapped_broadcast(
            &proxy_cfg("0.0.0.0:80", &[]),
            &api_cfg("0.0.0.0:9527"),
            &security_cfg(&["127.0.0.1", "10.0.0.0/8"]),
        );
        assert!(lines.is_empty(), "{}", rendered(&lines));
    }

    /// A mapped allowlist entry is named, with its replacement, and warned
    /// about — this is the entry an operator most plausibly added to work
    /// around the old fail-closed behaviour.
    #[test]
    fn mapped_allowlist_entry_is_named() {
        let lines = mapped_broadcast(
            &proxy_cfg("0.0.0.0:80", &[]),
            &api_cfg("0.0.0.0:9527"),
            &security_cfg(&["::ffff:127.0.0.1", "10.0.0.1"]),
        );
        let warn = lines
            .iter()
            .find(|l| l.level == BroadcastLevel::Warn)
            .unwrap_or_else(|| panic!("expected a warning, got: {}", rendered(&lines)));
        assert!(warn.text.contains("admin_ip_allowlist"), "{}", warn.text);
        assert!(warn.text.contains("::ffff:127.0.0.1 (use 127.0.0.1)"), "{}", warn.text);
        // The correctly-written entry must not be dragged in.
        assert!(!warn.text.contains("10.0.0.1 (use"), "{}", warn.text);
    }

    #[test]
    fn mapped_trusted_proxy_entry_is_named() {
        let lines = mapped_broadcast(
            &proxy_cfg("0.0.0.0:80", &["::ffff:10.0.0.0/104"]),
            &api_cfg("0.0.0.0:9527"),
            &security_cfg(&[]),
        );
        let warn = lines
            .iter()
            .find(|l| l.level == BroadcastLevel::Warn)
            .unwrap_or_else(|| panic!("expected a warning, got: {}", rendered(&lines)));
        assert!(warn.text.contains("trusted_proxies"), "{}", warn.text);
        assert!(
            warn.text.contains("::ffff:10.0.0.0/104 (use 10.0.0.0/8)"),
            "{}",
            warn.text
        );
    }

    /// Genuine IPv6 entries are correct and must never be flagged.
    #[test]
    fn genuine_ipv6_entries_are_not_flagged() {
        let lines = mapped_broadcast(
            &proxy_cfg("0.0.0.0:80", &["2001:db8::/32"]),
            &api_cfg("0.0.0.0:9527"),
            &security_cfg(&["::1", "fe80::1"]),
        );
        assert!(lines.is_empty(), "{}", rendered(&lines));
    }

    /// A `[::]` bind is what produces mapped addresses, so it gets an
    /// explanatory line naming exactly which listeners are affected.
    #[test]
    fn ipv6_wildcard_listener_explains_normalization() {
        let lines = mapped_broadcast(&proxy_cfg("[::]:80", &[]), &api_cfg("0.0.0.0:9527"), &security_cfg(&[]));
        let text = rendered(&lines);
        assert!(text.contains("[proxy] listen_addr"), "{text}");
        assert!(!text.contains("[api] listen_addr"), "{text}");
        assert!(text.contains("normalized to plain IPv4"), "{text}");
    }

    /// A disabled HTTP/3 listener is not reported even if it is v6-wildcard.
    #[test]
    fn disabled_http3_listener_is_not_reported() {
        let http3 = waf_common::config::Http3Config {
            enabled: false,
            listen_addr: "[::]:443".to_string(),
            ..waf_common::config::Http3Config::default()
        };
        let lines = ipv4_mapped_config_startup_broadcast(
            &proxy_cfg("0.0.0.0:80", &[]),
            &api_cfg("0.0.0.0:9527"),
            &http3,
            &security_cfg(&[]),
        );
        assert!(lines.is_empty(), "{}", rendered(&lines));

        let enabled = waf_common::config::Http3Config { enabled: true, ..http3 };
        let lines = ipv4_mapped_config_startup_broadcast(
            &proxy_cfg("0.0.0.0:80", &[]),
            &api_cfg("0.0.0.0:9527"),
            &enabled,
            &security_cfg(&[]),
        );
        assert!(rendered(&lines).contains("[http3] listen_addr"), "{}", rendered(&lines));
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
    use waf_storage::models::{CreateHost, Host};

    fn database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
    }

    /// A seed row with a unique hostname so parallel/repeated test runs never
    /// collide, and a `remote_ip` set on purpose.
    ///
    /// `remote_ip` is the `hosts` table's one `INET` column and sqlx is built
    /// without an `INET` codec, so it is the field a seed helper is most likely
    /// to break on. Populating it means these restart tests exercise the
    /// `host(remote_ip)` projection rather than tiptoeing around it.
    fn seed_req(prefix: &str, log_only_mode: bool, defense_config: Option<waf_common::DefenseConfig>) -> CreateHost {
        CreateHost {
            host: format!("{prefix}-{}.test", Uuid::new_v4()),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            remote_ip: Some("203.0.113.7".to_string()),
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            log_only_mode,
            defense_config,
        }
    }

    /// Persist a host row through the same `create_host` the admin API uses.
    ///
    /// Going through the repo rather than hand-rolling an `INSERT ...
    /// RETURNING *` is deliberate: `RETURNING *` drags in the raw `INET`
    /// `remote_ip`, which the `Host` model decodes as `Option<String>` and sqlx
    /// (built without the `ipnetwork` feature) cannot decode. `create_host`
    /// projects through the shared `host(remote_ip)` column list, so the seed
    /// path and the production path can never drift.
    async fn seed_host(db: &Database, log_only_mode: bool) -> Host {
        db.create_host(seed_req("logonly-restart", log_only_mode, None))
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
    /// (all other detectors left on). Goes through `create_host` for the same
    /// reason `seed_host` does.
    async fn seed_host_with_sqli(db: &Database, sqli: bool) -> Host {
        let defense = waf_common::DefenseConfig {
            sqli,
            ..waf_common::DefenseConfig::default()
        };
        db.create_host(seed_req("defense-restart", false, Some(defense)))
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

    // ── CrowdSec bouncer startup broadcast ───────────────────────────────────
    //
    // Every state in which the decision cache starts empty is a fail-open
    // window, and the broadcast is the only place an operator learns about it
    // at boot. These pin each of those states to a WARN and to wording that
    // names the consequence, so a future refactor cannot quietly downgrade one
    // of them to a reassuring INFO.

    fn bouncer_config() -> waf_engine::CrowdSecConfig {
        waf_engine::CrowdSecConfig {
            enabled: true,
            lapi_url: "http://127.0.0.1:8080".to_string(),
            ..waf_engine::CrowdSecConfig::default()
        }
    }

    #[test]
    fn a_restored_cache_is_reported_as_the_source_of_the_decisions() {
        let restore = waf_engine::RestoreOutcome {
            enabled: true,
            restored: 42,
            skipped_expired: 3,
            skipped_filtered: 1,
            error: None,
        };
        let lines = crowdsec_startup_broadcast(&bouncer_config(), true, &restore);
        assert!(
            lines.iter().all(|l| l.level == BroadcastLevel::Info),
            "a populated cache is not a warning"
        );
        let first = lines.first().expect("broadcast is never empty");
        assert!(
            first.text.contains("RESTORED") && first.text.contains("42"),
            "the restored count must be stated: {}",
            first.text
        );
        assert!(
            lines
                .iter()
                .any(|l| l.text.contains("evicts every restored entry it does not confirm")),
            "the operator must be told restored entries are provisional"
        );
    }

    #[test]
    fn a_disabled_mirror_warns_that_the_fail_open_window_is_back() {
        let lines = crowdsec_startup_broadcast(&bouncer_config(), false, &waf_engine::RestoreOutcome::default());
        let line = lines.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(
            line.text.contains("persist_decisions=false") && line.text.contains("allowed through"),
            "unexpected disabled-mirror line: {}",
            line.text
        );
    }

    #[test]
    fn an_unreadable_mirror_warns_with_the_underlying_error() {
        let restore = waf_engine::RestoreOutcome {
            enabled: true,
            error: Some("connection refused".to_string()),
            ..waf_engine::RestoreOutcome::default()
        };
        let lines = crowdsec_startup_broadcast(&bouncer_config(), true, &restore);
        let line = lines.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(
            line.text.contains("UNREADABLE") && line.text.contains("connection refused"),
            "unexpected unreadable-mirror line: {}",
            line.text
        );
    }

    #[test]
    fn an_empty_mirror_warns_that_nothing_is_enforced_yet() {
        let restore = waf_engine::RestoreOutcome {
            enabled: true,
            ..waf_engine::RestoreOutcome::default()
        };
        let lines = crowdsec_startup_broadcast(&bouncer_config(), true, &restore);
        let line = lines.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(
            line.text.contains("EMPTY") && line.text.contains("matches no IP"),
            "unexpected empty-mirror line: {}",
            line.text
        );
    }

    /// `fallback_action = "block"` turns a `CrowdSec` outage into a site outage.
    /// An operator has to be told at boot, not by a pager.
    #[test]
    fn a_fail_closed_fallback_is_announced_at_startup() {
        let config = waf_engine::CrowdSecConfig {
            fallback_action: waf_engine::crowdsec::config::FallbackAction::Block,
            ..bouncer_config()
        };
        let restore = waf_engine::RestoreOutcome {
            enabled: true,
            restored: 5,
            ..waf_engine::RestoreOutcome::default()
        };
        let line = crowdsec_startup_broadcast(&config, true, &restore)
            .into_iter()
            .find(|l| l.text.contains("fallback_action=BLOCK"))
            .expect("fail-closed must be broadcast");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(
            line.text.contains("REFUSES EVERY REQUEST"),
            "the consequence must be stated in full: {}",
            line.text
        );
    }

    /// The compatibility guarantee, stated as a test: the default posture adds
    /// nothing to the broadcast, so nothing about the shipped configuration
    /// changed.
    #[test]
    fn the_default_fallback_adds_no_line() {
        let restore = waf_engine::RestoreOutcome {
            enabled: true,
            restored: 5,
            ..waf_engine::RestoreOutcome::default()
        };
        let lines = crowdsec_startup_broadcast(&bouncer_config(), true, &restore);
        assert!(
            !lines.iter().any(|l| l.text.contains("fallback_action=")),
            "fallback_action=allow is the historical behaviour and needs no announcement"
        );
    }

    #[test]
    fn a_log_fallback_is_announced_without_alarming() {
        let config = waf_engine::CrowdSecConfig {
            fallback_action: waf_engine::crowdsec::config::FallbackAction::Log,
            ..bouncer_config()
        };
        let line = crowdsec_startup_broadcast(&config, true, &waf_engine::RestoreOutcome::default())
            .into_iter()
            .find(|l| l.text.contains("fallback_action=LOG"))
            .expect("log posture must be broadcast");
        assert_eq!(
            line.level,
            BroadcastLevel::Info,
            "log does not block, so it is not a warning"
        );
        assert!(line.text.contains("crowdsec:lapi-unavailable"));
    }

    #[test]
    fn appsec_only_mode_does_not_claim_a_bouncer_fail_open_window() {
        let config = waf_engine::CrowdSecConfig {
            mode: waf_engine::crowdsec::config::CrowdSecMode::Appsec,
            // Set even though it cannot apply: the cache is off the request
            // path in this mode, so the broadcast must not promise it does.
            fallback_action: waf_engine::crowdsec::config::FallbackAction::Block,
            ..bouncer_config()
        };
        let lines = crowdsec_startup_broadcast(&config, false, &waf_engine::RestoreOutcome::default());
        let line = lines.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Info);
        assert!(
            line.text.contains("mode=appsec"),
            "unexpected appsec line: {}",
            line.text
        );
        assert!(
            !lines.iter().any(|l| l.text.contains("fallback_action=BLOCK")),
            "mode=appsec never consults the bouncer cache, so it must not announce a fail-closed bouncer"
        );
    }

    // ── `rules` read helpers ─────────────────────────────────────────────────

    fn descriptor(id: &str, crs_id: Option<u32>, name: &str, category: &str, state: RuleState) -> RuleDescriptor {
        RuleDescriptor {
            id: id.to_owned(),
            crs_id,
            name: name.to_owned(),
            category: category.to_owned(),
            source: "rules/owasp-crs/sqli.yaml".to_owned(),
            severity: "critical",
            score: 5,
            paranoia: 1,
            phase: "request",
            declared_action: "score",
            state,
        }
    }

    /// The three numbers `rules list`, `rules search` and `rules stats` print
    /// are one computation, so the same rule set cannot produce three answers.
    #[test]
    fn state_counts_partition_the_rule_set() {
        let rules = vec![
            descriptor("CRS-942100", Some(942_100), "SQLi", "sqli", RuleState::Active),
            descriptor("CRS-942110", Some(942_110), "SQLi", "sqli", RuleState::Disabled),
            descriptor("CRS-941100", Some(941_100), "XSS", "xss", RuleState::LogOnly),
            descriptor("CRS-941110", Some(941_110), "XSS", "xss", RuleState::Active),
        ];
        let (active, disabled, log_only) = state_counts(&rules);
        assert_eq!((active, disabled, log_only), (2, 1, 1));
        assert_eq!(active + disabled + log_only, rules.len(), "every rule is counted once");
        assert_eq!(phase_count(&rules, "request"), 4);
        assert_eq!(phase_count(&rules, "response"), 0);
    }

    /// A search hit is always a rule the listing shows: the query is matched
    /// against the descriptor, never against a second copy of the rule files.
    #[test]
    fn search_matches_id_crs_number_name_category_and_source() {
        let rule = descriptor("CRS-942100", Some(942_100), "SQL Injection", "sqli", RuleState::Active);
        for needle in ["crs-942100", "942100", "sql injection", "sqli", "owasp-crs/sqli.yaml"] {
            assert!(rule_matches_query(&rule, needle), "should match {needle:?}");
        }
        assert!(!rule_matches_query(&rule, "xss"));
        // The severity/state columns are not search keys — matching them would
        // make "critical" return most of the rule set.
        assert!(!rule_matches_query(&rule, "critical"));
    }

    /// `rules reload` prints a command an operator can run. A bind address is
    /// not always a connectable one, so the wildcard binds resolve to loopback.
    #[test]
    fn admin_api_origin_turns_a_bind_address_into_a_reachable_one() {
        assert_eq!(admin_api_origin("0.0.0.0:9527"), "http://127.0.0.1:9527");
        assert_eq!(admin_api_origin("[::]:9527"), "http://127.0.0.1:9527");
        assert_eq!(admin_api_origin("127.0.0.1:19527"), "http://127.0.0.1:19527");
        assert_eq!(admin_api_origin("[::1]:9527"), "http://[::1]:9527");
        // Not a socket address: echoed back rather than replaced with a guess.
        assert_eq!(admin_api_origin("waf.internal:9527"), "http://waf.internal:9527");
    }

    /// The thread count must reach Pingora, not merely land in the WAF's own
    /// config struct: `ServerConf::threads` is the single field the proxy
    /// service's runtime is sized from
    /// (`pingora-core-0.8.1/src/server/mod.rs:705`).
    #[test]
    fn proxy_server_conf_carries_the_worker_thread_count() {
        let conf = proxy_server_conf(12, None, 30).expect("default Pingora conf must build");
        assert_eq!(conf.threads, 12);
        // Pingora's own default is the value this whole change exists to stop
        // inheriting; assert it is what we would have got, so the test fails if
        // an upstream bump ever makes the wiring redundant without saying so.
        assert_eq!(
            pingora_core::server::configuration::ServerConf::new()
                .expect("default conf")
                .threads,
            1
        );
    }

    /// The handover socket has to reach Pingora on the same field both halves
    /// read (`server/mod.rs:283` sending, `bootstrap_services.rs:98`
    /// receiving), and it has to displace the shipped default rather than sit
    /// beside it — that default is a path in a world-writable directory.
    #[test]
    fn proxy_server_conf_carries_the_handover_socket() {
        let sock = upgrade::UpgradeSock {
            path: PathBuf::from("/run/prx-waf/upgrade.sock"),
            source: upgrade::SockSource::Configured,
        };
        let conf = proxy_server_conf(4, Some(&sock), 30).expect("default Pingora conf must build");
        assert_eq!(conf.upgrade_sock, "/run/prx-waf/upgrade.sock");
        assert_eq!(
            conf.upgrade_sock_connect_accept_max_retries,
            Some(upgrade::HANDOVER_SOCK_RETRIES)
        );
        assert_eq!(
            pingora_core::server::configuration::ServerConf::new()
                .expect("default conf")
                .upgrade_sock,
            "/tmp/pingora_upgrade.sock"
        );
    }

    /// The drain budget has to displace Pingora's `None`, which is not "no
    /// wait" but a five-minute unconditional sleep (`server/mod.rs:56`, applied
    /// at `:775`) that holds the management ports and the database pool open
    /// long after the handover is done.
    #[test]
    fn proxy_server_conf_replaces_pingoras_five_minute_stop() {
        let conf = proxy_server_conf(1, None, 45).expect("default Pingora conf must build");
        assert_eq!(conf.grace_period_seconds, Some(45));
        assert_eq!(
            pingora_core::server::configuration::ServerConf::new()
                .expect("default conf")
                .grace_period_seconds,
            None,
            "upstream still leaves this unset, so the wiring is still needed"
        );
    }

    /// The startup line is the only place an operator reads back the derived
    /// path, so it must name it, and it must say which order the two commands
    /// go in — the reverse order is a shutdown.
    #[test]
    fn the_handover_broadcast_names_the_socket_and_the_order() {
        let sock = upgrade::UpgradeSock {
            path: PathBuf::from("/tmp/prx-waf-1000/upgrade.sock"),
            source: upgrade::SockSource::UserTemp,
        };
        let lines = handover_startup_broadcast(Some(&sock), false, 30);
        let line = lines.first().expect("an available handover is announced");
        assert!(line.text.contains("/tmp/prx-waf-1000/upgrade.sock"), "{}", line.text);
        assert!(line.text.contains("run --upgrade"), "{}", line.text);
        assert!(line.text.contains("SIGQUIT"), "{}", line.text);

        let taking_over = handover_startup_broadcast(Some(&sock), true, 30);
        let line = taking_over.first().expect("a handover launch is announced");
        assert!(line.text.contains("TAKING OVER"), "{}", line.text);
    }

    /// The stop drain is announced even when no handover is possible: it is
    /// what an ordinary `systemctl stop` costs, and the value it replaced was
    /// five minutes.
    #[test]
    fn the_drain_is_announced_whether_or_not_a_handover_is_possible() {
        for sock in [
            None,
            Some(upgrade::UpgradeSock {
                path: PathBuf::from("/run/prx-waf/upgrade.sock"),
                source: upgrade::SockSource::SystemRuntime,
            }),
        ] {
            let lines = handover_startup_broadcast(sock.as_ref(), false, 45);
            let drain = lines
                .iter()
                .find(|l| l.text.starts_with("Stop drain"))
                .expect("the drain is always announced");
            assert!(drain.text.contains("45s"), "{}", drain.text);
            assert!(drain.text.contains("drain_timeout_secs"), "{}", drain.text);
        }
    }

    /// A default install must be told the count, since it appears in no config
    /// file, and must be told that the figure is an affinity/quota number
    /// rather than the host's core count.
    #[test]
    fn worker_thread_broadcast_names_the_count_and_its_source() {
        let lines = worker_thread_startup_broadcast(WorkerThreadPlan::resolve(None, Some(16)));
        let line = lines.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Info);
        assert!(line.text.contains("Proxy worker threads: 16"), "{}", line.text);
        assert!(line.text.contains("worker_threads is unset"), "{}", line.text);
        assert!(line.text.contains("available_parallelism"), "{}", line.text);
        assert!(line.text.contains("cgroup CPU quota"), "{}", line.text);
    }

    /// One thread on a host that offered more is the ceiling the key exists to
    /// lift, so it is a warning with a remedy — whether it was asked for or
    /// arrived by a failed detection.
    #[test]
    fn worker_thread_broadcast_warns_on_a_single_thread_data_plane() {
        let fixed = worker_thread_startup_broadcast(WorkerThreadPlan::resolve(Some(1), Some(16)));
        let line = fixed.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(line.text.contains("THROUGHPUT CEILING"), "{}", line.text);
        assert!(line.text.contains("Raise [proxy] worker_threads"), "{}", line.text);

        let undetected = worker_thread_startup_broadcast(WorkerThreadPlan::resolve(None, None));
        let line = undetected.first().expect("broadcast is never empty");
        assert_eq!(line.level, BroadcastLevel::Warn);
        assert!(line.text.contains("could not be detected"), "{}", line.text);
        assert!(line.text.contains("THROUGHPUT CEILING"), "{}", line.text);
    }

    /// A multi-threaded data plane is not a warning — on a single-CPU host,
    /// one thread is not one either.
    #[test]
    fn worker_thread_broadcast_stays_informational_when_there_is_no_ceiling() {
        for plan in [
            WorkerThreadPlan::resolve(Some(4), Some(16)),
            WorkerThreadPlan::resolve(Some(0), Some(2)),
            WorkerThreadPlan::resolve(None, Some(1)),
        ] {
            let lines = worker_thread_startup_broadcast(plan);
            assert_eq!(
                lines.first().expect("broadcast is never empty").level,
                BroadcastLevel::Info,
                "unexpected warning for {plan:?}"
            );
        }
    }

    /// The shipped `configs/default.toml` must not pin the data plane: an
    /// operator who edits nothing gets every CPU the process may use.
    #[test]
    fn shipped_default_config_does_not_pin_the_data_plane() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/default.toml");
        let cfg = load_config(path).expect("shipped default.toml must load");
        assert_eq!(
            cfg.proxy.worker_threads, None,
            "the shipped config must leave worker_threads unset so it follows the available CPUs"
        );
        assert_eq!(
            cfg.proxy.worker_thread_plan().source,
            WorkerThreadSource::DefaultFollowsCpus
        );
    }
}
