# Changing prx-waf without dropping connections

A prx-waf process can hand its listening sockets to a replacement before it
exits, so the port never stops listening and requests already in flight finish
against the process that accepted them. That is how you apply a configuration
change, a rule-file change, or a new binary without an outage.

This is Pingora's zero-downtime upgrade with prx-waf's decisions layered on it.
The whole procedure is two commands.

---

## The procedure

```bash
# 1. Start the replacement. It binds nothing yet; it waits for the handover.
prx-waf --config /etc/prx-waf/config.toml run --upgrade

# 2. In another shell: hand over. Take the pid from the running process.
kill -QUIT "$(pgrep -f 'prx-waf .* run$')"
```

The order is not interchangeable, and getting it wrong is the one way to turn
an upgrade into an outage — see [When it goes wrong](#when-it-goes-wrong).

What happens between those two commands:

1. The replacement creates the handover socket and waits on it, for up to 60
   seconds. It holds no listener and has taken nothing.
2. `SIGQUIT` reaches the running process. It sends its listening file
   descriptors across the socket and logs `listener sockets sent`.
3. The replacement adopts those descriptors — the *same* kernel sockets, same
   inode, same accept queue — and starts serving. Nothing rebinds, so there is
   no instant at which the port is unlistened and no connection in the accept
   queue is lost.
4. The outgoing process waits 5 seconds, then stops accepting and broadcasts
   graceful shutdown. Requests it had already accepted keep running for
   `[proxy] drain_timeout_secs` (30 by default) plus 5 seconds of runtime
   shutdown, and then it exits on its own.

Both processes serve traffic between steps 3 and 4. That is intended: it is
what makes the in-flight requests survive.

The whole thing takes about 40 seconds at the shipped drain, nearly all of it
step 4. See [The drain](#the-drain) for why that number is what it is and when
to change it.

Verify afterwards:

```bash
curl -fsS http://127.0.0.1:9527/health     # admin API answers on the new process
pgrep -f 'prx-waf .* run'                  # exactly one pid, and it is the new one
```

---

## What survives and what does not

| | Across a handover |
| --- | --- |
| HTTP/1.1 and HTTP/2 on `[proxy] listen_addr` | **Preserved.** The socket is handed over; requests in flight complete on the old process. |
| HTTP/3 on `[http3] listen_addr` | **Dropped.** Clients reconnect. |
| Admin API on `[api] listen_addr` | Unavailable for the length of the overlap, then back on the new process. |
| Metrics on `[metrics] listen_addr` | Same as the admin API. Scrapes during the overlap fail; counters restart from zero on the new process. |
| Cluster membership | The new process rejoins as a new node instance. |
| Response cache, rate-limit buckets, CrowdSec decision cache | In-memory, so all rebuilt. Persisted CrowdSec decisions are reloaded before the new process serves (`persist_decisions`). |

**Why HTTP/3 cannot be preserved.** It is QUIC over UDP, and QUIC connection
state — keys, streams, congestion state — lives inside the process, not in the
kernel socket. Handing the descriptor over would give the new process packets it
cannot decrypt. This is a property of QUIC, not a gap in the implementation.

**Why the admin API and metrics are unavailable during the overlap.** They are
ordinary TCP listeners on their own runtimes, outside the descriptor table
Pingora hands across, and the outgoing process holds those ports until it exits.
The incoming process retries the bind for two minutes and comes up as soon as
they are released, logging one line per attempt. Both are management-plane
surfaces; the data plane is unaffected throughout.

**Database connections.** Both processes hold a pool for the length of the
overlap, so the peak is twice `[storage] max_connections` — 40 at the shipped
20. Size `2 × max_connections`, plus whatever else uses the database, under
Postgres's `max_connections` (100 by default), or the incoming process will fail
to open its pool while the outgoing one is still draining. Raising the drain
lengthens that overlap; it does not change its size.

---

## The drain

```toml
[proxy]
drain_timeout_secs = 30   # the default
```

or `PRXWAF_DRAIN_TIMEOUT_SECS`. It is how long a process keeps serving
already-accepted requests after it is told to stop, and it applies to a plain
`SIGTERM` exactly as it applies to a handover.

**It is a fixed wait, not a drain detector.** Pingora sleeps the whole period
whether or not anything is still in flight, then gives the runtimes five more
seconds before cutting them. So the number is the cost of every stop, not a
worst case, and every second of it is a second of two processes, two database
pools, and no management API.

Pingora's own default — which prx-waf inherited until this was wired up — is
**300 seconds**. That made an in-place upgrade a five-minute overlap and a
`systemctl stop` a five-minute hang that systemd ends with `SIGKILL` at ninety
seconds anyway, severing exactly the connections the wait was meant to protect.

Size it above the longest request this proxy should be allowed to finish, and
below your supervisor's kill timeout — `TimeoutStopSec` under systemd,
`terminationGracePeriodSeconds` in Kubernetes. If you proxy WebSocket or SSE,
note that those connections are not "requests that finish": they will be cut at
the end of the drain whatever you set it to, so pick the value for your ordinary
traffic and expect long-lived streams to reconnect.

`0` skips the wait and leaves only the five-second runtime shutdown.

---

## The handover socket

The two processes rendezvous over a Unix socket. Its location is announced at
startup by both:

```
Graceful upgrade: available on /run/prx-waf/upgrade.sock (derived — the system
runtime directory, which this process owns). To change the configuration or the
binary without dropping connections, start the new process with
`prx-waf run --upgrade` FIRST and only then send this one SIGQUIT.
```

By default the path is derived, not configured, so both halves agree on it
without either being set up:

| Running as | Socket |
| --- | --- |
| root | `/run/prx-waf/upgrade.sock` |
| anyone else | `/tmp/prx-waf-<uid>/upgrade.sock` |

The derivation reads no environment variable, deliberately. A path that
depended on `RUNTIME_DIRECTORY` would resolve one way under systemd and another
way from an operator's shell, and the two halves would miss each other with
nothing to show for it but a timeout.

### This is a security boundary

Pingora chmods the socket itself to `0666` at creation, so the socket carries no
access control of its own — **the directory is the entire boundary**. Whoever
can create a socket at that path while an upgrade is in flight receives the
listening descriptors for the port this WAF fronts, and can then accept and
answer traffic for the sites behind it. Whoever can merely reach the socket can
connect first and hang the handover.

prx-waf therefore creates the directory mode `0700` at creation time (not
`mkdir` followed by `chmod`, which leaves a window), and refuses a directory
that already exists unless it is a real directory, owned by this process's
effective uid, and grants nothing to group or other. Pingora's own shipped
default — `/tmp/pingora_upgrade.sock`, directly in a world-writable directory —
is exactly the arrangement this refuses.

On a normal start a refusal is a warning: the WAF runs, and only the ability to
upgrade in place is lost. On a `run --upgrade` start it is fatal, since that is
the only thing the launch was for; nothing has been signalled at that point, so
the running process keeps serving.

### Moving it

```toml
[proxy]
upgrade_sock = "/var/lib/prx-waf/run/upgrade.sock"
```

or `PRXWAF_UPGRADE_SOCK=/var/lib/prx-waf/run/upgrade.sock`. A configured path is
held to the same directory rules, and is refused rather than quietly relocated:
the other half of the handover is reading the same setting, so silently moving
it would break the upgrade instead of the boot.

Both processes must resolve the same path. If you set it, set it in the config
file both read.

---

## Under a supervisor

systemd, or any supervisor that tracks a main pid, needs to be told that the pid
changes. There are two workable arrangements.

**Detach the upgrade from the unit.** Keep the unit for cold starts, and run the
handover by hand or from a deploy script. The replacement is not a child of
systemd, so `systemctl status` will be stale until the next `systemctl restart`
— acceptable for a deploy pipeline that knows what it did, not for a fleet
managed only through systemd.

**Let systemd own only the socket path.** Give the unit a `RuntimeDirectory` and
pin `upgrade_sock` into it, so the directory exists with the right ownership and
is cleaned up on stop:

```ini
[Service]
User=prx-waf
RuntimeDirectory=prx-waf
RuntimeDirectoryMode=0700
Environment=PRXWAF_UPGRADE_SOCK=/run/prx-waf/upgrade.sock
ExecStart=/usr/local/bin/prx-waf --config /etc/prx-waf/config.toml run
```

`RuntimeDirectoryMode=0700` is required, not decorative — systemd's default is
`0755`, which prx-waf refuses for the reason above.

Note that `Type=simple` still cannot follow the pid across a handover.
`Type=forking` with a pid file does not help either, because the replacement is
started as a separate command rather than forked by the outgoing process.
Treating in-place upgrades as an operation the deploy tooling performs, and
`systemctl restart` as the (connection-dropping) fallback, is the honest
arrangement today.

## In a container

An in-place upgrade needs both processes in the same network, mount and PID
namespaces — i.e. both inside the same running container:

```bash
podman exec -d prx-waf /usr/local/bin/prx-waf --config /etc/prx-waf/config.toml run --upgrade
podman exec prx-waf pkill -QUIT -f 'prx-waf .* run$'
```

The replacement then becomes the container's long-lived process while PID 1 is
the one that exits, which most runtimes treat as the container stopping. Unless
your image has an init that tolerates that, the ordinary container answer is a
rolling replacement at the orchestrator level — start a new container, shift
traffic, stop the old one — which achieves the same result one layer up.

---

## When it goes wrong

**`SIGQUIT` with nothing waiting is a shutdown, not an upgrade.** The outgoing
process spends its retry budget trying to hand descriptors to a socket nobody is
listening on, then exits gracefully anyway, and the port is left unserved until
something binds it again. Always start the replacement first and wait for its
`Waiting up to 60s for the running prx-waf to hand over…` line.

**The replacement fails to start.** Bad config, bad binary, unusable socket
directory: it exits and the running process, which has not been signalled, keeps
serving. This is why the order is what it is — every failure mode of the new
process is harmless as long as you have not sent the signal yet. Read its log,
fix, try again.

**The replacement gives up waiting.** After 60 seconds without a handover it
logs `Bootstrap failed on error` and exits. Same situation: nothing was
signalled, the running process is untouched.

**`[proxy] listen_addr` differs between the two.** The descriptors are looked up
by the literal bind string, so a changed address matches nothing, and the new
process tries to bind a port the old one still holds. Change the listen address
with a restart, not with a handover.

**Both processes are still alive.** For `drain_timeout_secs` plus five seconds,
that is the design — see [The drain](#the-drain). Beyond that, `SIGINT` to the
outgoing process is the fast, connection-dropping way to end it.
