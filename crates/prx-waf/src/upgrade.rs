//! Zero-downtime handover of the proxy listeners between two prx-waf processes.
//!
//! Pingora already owns both halves of the mechanism: the outgoing process
//! sends its listening file descriptors over a Unix socket when it takes
//! `SIGQUIT` (`pingora-core-0.8.1/src/server/mod.rs:283`), and the incoming
//! process picks them up during `bootstrap()` — but only when its `Opt.upgrade`
//! is set (`pingora-core-0.8.1/src/server/bootstrap_services.rs:172`). prx-waf
//! passed `None` for the options, so the receiving half was never armed and a
//! `SIGQUIT` was a plain shutdown with a five-second stall in it.
//!
//! This module supplies the three things that had to be decided locally:
//!
//! * **where the handover socket lives**, and the refusal to use a directory
//!   that would let a local user intercept the handover;
//! * **which launches try to take over**, kept on the command line rather than
//!   in the config file;
//! * **what the listeners Pingora does not carry do** while the outgoing
//!   process still owns their ports.

use std::fs::DirBuilder;
use std::future::Future;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// File name given to the handover socket inside whichever directory is chosen.
const SOCK_FILE_NAME: &str = "upgrade.sock";

/// Preferred automatic home for the handover socket: the system runtime
/// directory, which is where a root-run daemon's transient sockets belong and
/// which is wiped on reboot.
const SYSTEM_RUNTIME_DIR: &str = "/run/prx-waf";

/// How long the outgoing process is given to answer, in seconds.
///
/// Pingora's own default is five attempts at one second apart on both sides
/// (`transfer_fd/mod.rs:196`), which forces an operator to send `SIGQUIT`
/// within five seconds of starting the incoming process or watch it exit. That
/// is a stopwatch, not a procedure. A minute is long enough to paste a second
/// command, and it only ever elapses on a handover that has already failed.
pub const HANDOVER_SOCK_RETRIES: usize = 60;

/// How long a listener Pingora does not carry over keeps retrying its bind
/// while the outgoing process still holds the port.
///
/// The outgoing process releases the admin API, metrics and HTTP/3 ports only
/// when it exits, which is Pingora's five-second close timeout plus the
/// configured grace period plus however long the last in-flight request takes.
/// This window has to outlast that or the incoming process comes up with no
/// management plane; it is deliberately generous because the cost of waiting is
/// a log line and the cost of giving up early is a WAF that cannot be
/// administered until someone restarts it.
pub const HANDOVER_BIND_WINDOW: Duration = Duration::from_mins(2);

/// Interval between bind attempts inside [`HANDOVER_BIND_WINDOW`].
const HANDOVER_BIND_INTERVAL: Duration = Duration::from_secs(1);

/// Where the resolved socket path came from, for the startup line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockSource {
    /// `[proxy] upgrade_sock` or `PRXWAF_UPGRADE_SOCK`.
    Configured,
    /// Derived: the system runtime directory.
    SystemRuntime,
    /// Derived: a per-uid directory under `/tmp`, for a non-root process.
    UserTemp,
}

/// A handover socket path that has been resolved and whose parent directory has
/// been created and vetted.
#[derive(Debug, Clone)]
pub struct UpgradeSock {
    pub path: PathBuf,
    pub source: SockSource,
}

/// Why a candidate parent directory cannot hold the handover socket.
///
/// Pingora chmods the socket itself to 0666 so that a process which drops
/// privileges after binding can still reach it, which means the socket carries
/// no access control of its own: the directory is the entire boundary. A local
/// user who can create a path here wins the race against the incoming process,
/// receives the listening descriptors for the port this WAF fronts, and can
/// accept traffic on it. A local user who merely reaches the socket can connect
/// first and make the handover hang.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirVerdict {
    Usable,
    /// The path exists but is not a directory.
    NotADirectory,
    /// The path is a symlink, so what it names can change under us.
    Symlink,
    /// Owned by somebody else, who can therefore replace anything in it.
    ForeignOwner {
        owner: u32,
    },
    /// Reachable by group or other.
    TooPermissive {
        mode: u32,
    },
}

impl DirVerdict {
    /// Explain the verdict in the terms an operator has to act on.
    pub fn describe(self, dir: &Path) -> String {
        match self {
            Self::Usable => format!("{} is usable", dir.display()),
            Self::NotADirectory => format!("{} exists but is not a directory", dir.display()),
            Self::Symlink => format!(
                "{} is a symlink; the handover socket must sit in a real directory, because a link can be \
                 repointed between the check and the bind",
                dir.display()
            ),
            Self::ForeignOwner { owner } => format!(
                "{} is owned by uid {owner}, not by this process; its owner could replace the handover socket and \
                 receive this WAF's listening sockets",
                dir.display()
            ),
            Self::TooPermissive { mode } => format!(
                "{} is mode {mode:04o}; it must grant nothing to group or other (0700), because the handover socket \
                 inside it is chmod 0666 by Pingora and anyone who can reach it can intercept the listener handover",
                dir.display()
            ),
        }
    }
}

/// Judge a directory from its stat, without touching the filesystem.
pub const fn classify_dir(is_dir: bool, is_symlink: bool, owner: u32, mode: u32, euid: u32) -> DirVerdict {
    if is_symlink {
        return DirVerdict::Symlink;
    }
    if !is_dir {
        return DirVerdict::NotADirectory;
    }
    if owner != euid {
        return DirVerdict::ForeignOwner { owner };
    }
    let permission_bits = mode & 0o7777;
    if permission_bits & 0o077 != 0 {
        return DirVerdict::TooPermissive { mode: permission_bits };
    }
    DirVerdict::Usable
}

/// The automatic socket path for an effective uid.
///
/// Deliberately a pure function of the uid and nothing else. An earlier draft
/// consulted `RUNTIME_DIRECTORY`, which would have made the outgoing process
/// (started by a supervisor, with that variable set) and the incoming one
/// (started from an operator's shell, without it) resolve different paths and
/// fail the handover with no symptom but a timeout. A path that depends only on
/// who is running can be reasoned about from either side.
pub fn auto_sock_dirs(euid: u32) -> Vec<PathBuf> {
    vec![
        PathBuf::from(SYSTEM_RUNTIME_DIR),
        PathBuf::from(format!("/tmp/prx-waf-{euid}")),
    ]
}

/// This process's effective uid.
///
/// Through `nix` rather than a raw `libc::geteuid`, because the workspace denies
/// `unsafe_code` and this is the one fact about the process that std does not
/// expose. `nix` is already in the tree beneath Pingora.
fn effective_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Create `dir` (0700) if absent, then judge it.
fn prepare_dir(dir: &Path, euid: u32) -> io::Result<DirVerdict> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => Ok(classify_dir(
            meta.is_dir(),
            meta.file_type().is_symlink(),
            meta.uid(),
            meta.permissions().mode(),
            euid,
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Mode at creation rather than a chmod afterwards: the gap between
            // `create_dir` and `set_permissions` is a window in which the
            // directory exists at the umask's mode and anything may be written
            // into it.
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            let meta = std::fs::symlink_metadata(dir)?;
            Ok(classify_dir(
                meta.is_dir(),
                meta.file_type().is_symlink(),
                meta.uid(),
                meta.permissions().mode(),
                euid,
            ))
        }
        Err(e) => Err(e),
    }
}

/// Resolve the handover socket path and vet the directory it will live in.
///
/// A configured path is honoured or rejected — never silently relocated, since
/// the other half of the handover is reading the same setting. An automatic
/// path walks the candidates in preference order and takes the first that can
/// be made safe, which is the system runtime directory for a root-run daemon
/// and a per-uid directory under `/tmp` for anything else.
pub fn resolve(configured: Option<&str>) -> anyhow::Result<UpgradeSock> {
    let euid = effective_uid();

    if let Some(configured) = configured {
        let path = PathBuf::from(configured);
        let dir = path.parent().ok_or_else(|| {
            anyhow::anyhow!("[proxy] upgrade_sock = {configured:?} has no parent directory; it must be a path to a socket file, not a filesystem root")
        })?;
        let verdict = prepare_dir(dir, euid).map_err(|e| {
            anyhow::anyhow!("cannot prepare the directory of [proxy] upgrade_sock = {configured:?}: {e}")
        })?;
        if verdict != DirVerdict::Usable {
            anyhow::bail!(
                "[proxy] upgrade_sock = {configured:?} cannot be used: {}. Point it at a directory this process owns \
                 and that is mode 0700, or leave the setting unset to have one derived.",
                verdict.describe(dir)
            );
        }
        return Ok(UpgradeSock {
            path,
            source: SockSource::Configured,
        });
    }

    let mut rejections = Vec::new();
    for (dir, source) in auto_sock_dirs(euid)
        .into_iter()
        .zip([SockSource::SystemRuntime, SockSource::UserTemp])
    {
        match prepare_dir(&dir, euid) {
            Ok(DirVerdict::Usable) => {
                return Ok(UpgradeSock {
                    path: dir.join(SOCK_FILE_NAME),
                    source,
                });
            }
            Ok(verdict) => rejections.push(verdict.describe(&dir)),
            Err(e) => rejections.push(format!("{}: {e}", dir.display())),
        }
    }

    anyhow::bail!(
        "no directory is available to hold the graceful-upgrade handover socket ({}). Set [proxy] upgrade_sock \
         to a path in a directory this process owns and that is mode 0700.",
        rejections.join("; ")
    )
}

/// Does this error chain bottom out in "address already in use"?
///
/// Matched on the `io::ErrorKind` rather than on rendered text: every listener
/// this is applied to wraps its bind failure in its own context string, and
/// only the kind survives that intact.
pub fn is_address_in_use(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|io_err| io_err.kind() == io::ErrorKind::AddrInUse)
}

/// Run a listener, retrying while its port is still held by a process that is
/// on its way out.
///
/// `window` is `None` on an ordinary launch, which makes this a plain call: a
/// port that is taken on a normal start is somebody else's listener and waiting
/// two minutes to say so would only delay the diagnosis. On a handover launch
/// it is `Some`, and the contention is expected and temporary.
///
/// Only `AddrInUse` is retried. A permission error or a malformed address will
/// not resolve itself, and retrying them would turn an immediate, accurate
/// message into a slow one.
pub async fn serve_through_handover<F, Fut>(label: &str, window: Option<Duration>, serve: F) -> anyhow::Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let deadline = window.map(|w| Instant::now() + w);
    let mut waited = Duration::ZERO;
    loop {
        let err = match serve().await {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let Some(deadline) = deadline else { return Err(err) };
        if !is_address_in_use(&err) || Instant::now() >= deadline {
            return Err(err);
        }
        tracing::warn!(
            "{label}: the port is still held by the outgoing process after {}s of this handover; retrying in {}s \
             (giving up after {}s, at which point this listener stays down until the process is restarted)",
            waited.as_secs(),
            HANDOVER_BIND_INTERVAL.as_secs(),
            window.unwrap_or_default().as_secs(),
        );
        tokio::time::sleep(HANDOVER_BIND_INTERVAL).await;
        waited += HANDOVER_BIND_INTERVAL;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The only directory shape that may hold the socket is one this process
    /// owns outright and nobody else can reach.
    #[test]
    fn only_a_private_owned_directory_is_usable() {
        assert_eq!(classify_dir(true, false, 1000, 0o40700, 1000), DirVerdict::Usable);
    }

    /// `/tmp` itself is the shape this check exists to reject: world-writable,
    /// and the path Pingora ships as its default.
    #[test]
    fn a_world_writable_directory_is_refused() {
        assert_eq!(
            classify_dir(true, false, 0, 0o41777, 0),
            DirVerdict::TooPermissive { mode: 0o1777 }
        );
    }

    /// A group-readable directory is refused too: reaching the 0666 socket is
    /// enough to connect first and stall the handover, no write needed.
    #[test]
    fn a_group_reachable_directory_is_refused() {
        assert_eq!(
            classify_dir(true, false, 1000, 0o40750, 1000),
            DirVerdict::TooPermissive { mode: 0o750 }
        );
    }

    /// Somebody else's directory can have its contents replaced by them, which
    /// is exactly the interception this guards against.
    #[test]
    fn a_foreign_owned_directory_is_refused() {
        assert_eq!(
            classify_dir(true, false, 0, 0o40700, 1000),
            DirVerdict::ForeignOwner { owner: 0 }
        );
    }

    /// A symlink is judged before anything else, because what it resolves to
    /// can change between this stat and the bind.
    #[test]
    fn a_symlink_is_refused_whatever_it_points_at() {
        assert_eq!(classify_dir(true, true, 1000, 0o40700, 1000), DirVerdict::Symlink);
    }

    #[test]
    fn a_file_where_a_directory_belongs_is_refused() {
        assert_eq!(
            classify_dir(false, false, 1000, 0o100_600, 1000),
            DirVerdict::NotADirectory
        );
    }

    /// Both processes of a handover must derive the same path from the same
    /// uid, or the upgrade fails with nothing to show but a timeout.
    #[test]
    fn the_derived_path_depends_only_on_the_uid() {
        assert_eq!(auto_sock_dirs(1000), auto_sock_dirs(1000));
        assert_ne!(auto_sock_dirs(1000), auto_sock_dirs(1001));
        assert_eq!(auto_sock_dirs(0).first(), Some(&PathBuf::from("/run/prx-waf")));
        assert_eq!(auto_sock_dirs(1000).get(1), Some(&PathBuf::from("/tmp/prx-waf-1000")));
    }

    /// The retry hinges on recognising the kind through however many layers of
    /// context the listener wrapped its bind failure in.
    #[test]
    fn address_in_use_is_recognised_under_context() {
        let err = anyhow::Error::from(io::Error::from(io::ErrorKind::AddrInUse))
            .context("cannot bind the metrics listener")
            .context("starting prx-waf");
        assert!(is_address_in_use(&err));
    }

    /// Anything else must fall straight through, so a real misconfiguration is
    /// reported at once instead of after a two-minute retry loop.
    #[test]
    fn other_io_errors_are_not_treated_as_contention() {
        let err = anyhow::Error::from(io::Error::from(io::ErrorKind::PermissionDenied)).context("cannot bind");
        assert!(!is_address_in_use(&err));
        assert!(!is_address_in_use(&anyhow::anyhow!("not an io error at all")));
    }

    /// Without a handover window this is a plain call: one attempt, and the
    /// error surfaces immediately.
    #[tokio::test]
    async fn an_ordinary_launch_does_not_retry_a_taken_port() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result = serve_through_handover("test", None, || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(anyhow::Error::from(io::Error::from(io::ErrorKind::AddrInUse))) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A handover launch keeps trying until the outgoing process lets go.
    #[tokio::test]
    async fn a_handover_launch_retries_until_the_port_frees_up() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result = serve_through_handover("test", Some(Duration::from_mins(1)), || {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(anyhow::Error::from(io::Error::from(io::ErrorKind::AddrInUse)))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// A handover launch still refuses to loop on an error that will not clear.
    #[tokio::test]
    async fn a_handover_launch_does_not_retry_a_permission_error() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result = serve_through_handover("test", Some(Duration::from_mins(1)), || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(anyhow::Error::from(io::Error::from(io::ErrorKind::PermissionDenied))) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// A configured path in a world-writable directory is refused outright
    /// rather than quietly relocated: the other process is reading the same
    /// setting, so moving it here would break the handover instead of the boot.
    #[test]
    fn a_configured_path_in_a_public_directory_is_refused() {
        let err = resolve(Some("/tmp/prx-waf-handover-test.sock")).expect_err("/tmp is world-writable");
        let rendered = format!("{err}");
        assert!(rendered.contains("upgrade_sock"), "{rendered}");
        assert!(rendered.contains("0700"), "{rendered}");
    }

    /// The derived path must work with no configuration at all, on a machine
    /// where the process is not root.
    #[test]
    fn the_derived_path_resolves_without_configuration() {
        let sock = resolve(None).expect("a derived socket path must always be available");
        assert!(sock.path.ends_with(SOCK_FILE_NAME), "{}", sock.path.display());
        let dir = sock.path.parent().expect("the derived path has a parent");
        let meta = std::fs::symlink_metadata(dir).expect("the directory was prepared");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o700, "{}", dir.display());
    }
}
