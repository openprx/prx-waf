# Cluster Security Defaults: CA Key Replication & Declared Membership

This is an operator runbook, not an API reference. It covers two `[cluster]`
settings whose *only* effect is on security posture, both of which are easy to
get wrong because getting them wrong doesn't fail loudly — the cluster still
runs, it's just one incident away from a bad day.

| Setting | Safe default | What happens if you flip it the wrong way |
|---|---|---|
| `cluster.replicate_ca_key` | `false` (keep it) | Your cluster CA private key leaves the main node and is held by every worker. |
| `cluster.members` | unset in the shipped default, **but you must set it in production** | Election quorum silently shrinks with every dead/partitioned peer, down to 1 — a partitioned single node can crown itself Main. |

Read both sections before you touch either setting. They interact: a cluster
with no declared `members` is also the cluster where a compromised CA key (from
`replicate_ca_key`) does the most damage, because there's no fixed membership
list constraining who can mint a certificate and be believed.

---

## 1. `replicate_ca_key` — keep this `false`

### What it is

The cluster CA is a single Ed25519 keypair, generated once by the first main
node (`crates/waf-cluster/src/crypto/ca.rs:42`, `CertificateAuthority::generate`).
Its certificate is self-signed with `KeyCertSign` + `CrlSign` + `DigitalSignature`
usages (`crates/waf-cluster/src/crypto/ca.rs:25-29`) — i.e. it is explicitly
allowed to sign other certificates. Every node certificate in the cluster is
signed by this one key (`crates/waf-cluster/src/crypto/node_cert.rs:33-64`,
`NodeCertificate::generate`), and a node's identity in every protocol —
mTLS peer auth, join tokens, election vote grants — is "whatever `node_id` is
in the SAN of a certificate that chains to this CA." Holding the CA private
key means you can:

- Mint a certificate for *any* `node_id`, including one that impersonates an
  existing node or a node that was never provisioned.
- Forge join tokens: `generate_token`/`verify_token` derive their signing key
  directly from the CA key PEM (`crates/waf-cluster/src/crypto/token.rs:65-131`,
  `derive_signing_key` hashes `ca_key_pem`).
- Sign vote grants that the rest of the cluster will accept as genuine,
  because grant verification is "does this chain to the CA and match the
  claimed `node_id`" (`crates/waf-cluster/src/crypto/vote.rs`, consumed by
  `ElectionManager::process_result` in `crates/waf-cluster/src/election/mod.rs:570-664`).

In short: **the CA private key is the root of trust for the entire cluster.**
Anyone who has it can join as any node, win any election, and push rules/config
to every worker as the accepted Main.

By default, only the main node ever has this key in memory: it's either
generated in-process (`crates/waf-cluster/src/lib.rs:124-136`) or loaded from
the file at `cluster.crypto.ca_key` (`crates/waf-cluster/src/lib.rs:146-153`,
"CA key is optional — only the main node has it"). Workers are provisioned with
`ca_key = ""` and never read a CA key file at all
(`docs/cluster-guide.md:136`: "workers do NOT need the CA key").

### What flipping it on does

`cluster.replicate_ca_key` (`crates/waf-common/src/config.rs:1534-1538`,
default `false`) is checked in exactly one place: the main's handler for an
incoming `JoinRequest`
(`crates/waf-cluster/src/transport/server.rs:277-293`). When a worker joins:

```rust
let encrypted_ca_key_b64 = if node_state.config.replicate_ca_key && !ca_passphrase.is_empty() {
    // AES-256-GCM + Argon2id, keyed off cluster.crypto.ca_passphrase
    ...
} else {
    None
};
```

If `replicate_ca_key = true` **and** `cluster.crypto.ca_passphrase` is
non-empty, the main encrypts its CA private key
(`crates/waf-cluster/src/crypto/store.rs:108-128`, `encrypt_blob`, AES-256-GCM
with an Argon2id-derived key and a random salt) and ships the ciphertext to the
joining worker inside the `JoinResponse` (`crates/waf-cluster/src/protocol.rs:112-125`,
`encrypted_ca_key_b64`). The worker stores it in memory
(`crates/waf-cluster/src/transport/client.rs:275-282`,
`node_state.ca_key_encrypted`).

So enabling this setting means: **every worker that joins the cluster receives
a copy of your CA private key**, protected only by AES-GCM and whatever
strength `ca_passphrase` has. The security boundary of your entire cluster PKI
collapses from "one file on one host" to "one shared secret string that must be
configured identically on every node that might ever need to decrypt it."
Compromise any one worker's memory (core dump, debugger attach, swap, a
container escape) plus knowledge of `ca_passphrase` (which — to be useful for
failover — has to be distributed to every node that could become the new main,
i.e. potentially the whole fleet) and the attacker owns the cluster's root of
trust, not just that one node.

`ca_passphrase` itself is not a low bar to protect: `encrypt_blob` refuses
passphrases under 16 characters (`crates/waf-cluster/src/crypto/store.rs:41,
109-111`, `MIN_PASSPHRASE_LEN`), but a 16-character shared secret sitting in
plaintext in every node's TOML/env is still a single string that, if leaked
once, compromises every copy of the encrypted CA key sitting on every worker,
past and future.

### Known implementation gap (verify against the version you run)

As read from the current codebase, the encrypted blob a worker receives is
only ever *written* to `NodeState.ca_key_encrypted`
(`crates/waf-cluster/src/transport/client.rs:279`,
`crates/waf-cluster/src/node.rs:76`). There is no code path in
`promote_to_main()` (`crates/waf-cluster/src/node.rs:192-212`) or anywhere else
in `election/mod.rs` that decrypts `ca_key_encrypted` back into a usable
`ca_key_pem` when a worker actually gets promoted to Main. The comment at
`node.rs:203-204` ("it can be decrypted now using the cluster passphrase from
config — done by the caller when signing certs") describes intent, not
something wired up today.

Practically: as things stand, turning this on pays the full security cost
above and does **not** yet get you the automatic CA-failover it's meant to
enable — a promoted worker still won't be able to sign new node certs or
validate join tokens without the CA key being placed on it some other way
(e.g. manually copying `cluster-ca.key` to whichever node you intend to
promote, ahead of time, same as the non-replicated setup). Re-verify this
against `git blame`/the current source before relying on it — this is exactly
the kind of gap that gets fixed silently between versions.

### When there's a legitimate reason to enable it

Only if all of the following hold:

1. You have a real automatic-failover requirement (main-node loss must recover
   without an operator manually copying `cluster-ca.key` to the new main), and
2. You've confirmed the decrypt-on-promotion path actually exists in the
   version you're running (see gap above), and
3. Every node that could receive the encrypted key is inside the same trust
   boundary you'd put the CA key itself in — a compromised worker becomes
   equivalent to a compromised CA once this is on, so don't run workers in a
   lower-trust tier (e.g. a DMZ, a different security zone, a third party's
   infrastructure) than your main.

### Required companion measures if you do enable it

- Set `cluster.crypto.ca_passphrase` to a long, random, high-entropy secret
  (well above the 16-character floor) generated with a real CSPRNG, not a
  memorable phrase.
- Manage that passphrase like the CA key itself: a secrets manager, not a
  plaintext TOML committed anywhere or an env var dumped in a process listing.
  It must be identical across every node that might need to decrypt the
  replicated blob, which by construction is every node — plan key rotation
  accordingly (rotating it means re-encrypting and re-distributing to the
  whole fleet, not just the main).
- Set `cluster.members` (Section 2) so the pool of nodes able to receive the
  replicated key is fixed and audited, not "whoever presents a valid join
  token."
- Treat every worker's host/container as CA-key-custody infrastructure for
  access-control, logging, and patching purposes — because it now is.
- Monitor `ca_key_replicated = true` in the join-accept log line
  (`crates/waf-cluster/src/transport/server.rs:295-299`) so you have an audit
  trail of exactly which nodes received the key and when.

If you don't have a hard failover requirement: leave `replicate_ca_key =
false` (the default) and keep `cluster-ca.key` on the main node's disk only,
backed up out-of-band, restored manually on planned main promotion. That is
the only configuration in which a single compromised node cannot compromise
the whole cluster's PKI.

---

## 2. `cluster.members` — declare it explicitly in production

### What happens if you leave it unset

`cluster.members` defaults to an empty list
(`crates/waf-common/src/config.rs:1569`, `members: Vec::new()`) — this is the
default shipped in `configs/default.toml` and it is **not** safe for a
production multi-node deployment. Two things degrade when it's empty:

**a. Quorum size floats with the live peer view.**

`NodeState::quorum_total()` is what every election counts votes against:

```rust
// crates/waf-cluster/src/node.rs:256-268
pub async fn quorum_total(&self) -> usize {
    if self.config.members.is_empty() {
        self.total_nodes().await   // peers.len() + 1 — shrinks as peers are evicted
    } else {
        self.config.members.len()  // fixed, doesn't shrink
    }
}
```

Peers are evicted from the live view by the phi-accrual failure detector on a
background loop (`crates/waf-cluster/src/health/mod.rs:86-124`,
`run_peer_eviction`, ticking every `heartbeat_interval_ms * 3`,
`crates/waf-cluster/src/lib.rs:240`). Every eviction shrinks `total_nodes()`,
and — with `members` empty — shrinks the quorum denominator right along with
it.

Follow that to its conclusion: a node that gets partitioned away from the rest
of the cluster will, after enough missed heartbeats, evict every peer it can no
longer reach. Its own `total_nodes()` then reads back as `1`. The election loop
treats a total of `1` as a legitimate single-node cluster and self-promotes to
Main **without an election** when `members` is empty or is a 1-element list
containing only itself:

```rust
// crates/waf-cluster/src/election/mod.rs:703-716
if total_nodes <= 1 {
    let members = &node_state.config.members;
    let sole_declared_member =
        members.is_empty() || (members.len() == 1 && members.contains(&node_state.node_id));
    if sole_declared_member {
        info!(..., "Single-node cluster — claiming Main role without election");
        node_state.promote_to_main().await;
    } else {
        warn!(..., "Declared cluster membership does not permit single-node self-promotion; backing off");
        node_state.demote_to_worker().await;
    }
    continue;
}
```

With `members` empty, this code has no way to distinguish "this really is a
one-node deployment" from "this is one surviving node of a five-node cluster
that just got network-partitioned from the other four." Both look identical:
`total_nodes() == 1` and `members.is_empty()`. The partitioned node crowns
itself Main, and if the other side of the partition still has a working
quorum, you now have two Mains simultaneously accepting writes and pushing
rule/config updates — split-brain.

This is the exact failure mode M-16 was written to close
(`crates/waf-cluster/src/election/mod.rs:26-27, 94-96`, doc comments
explicitly calling out that quorum is measured against declared `members`
"so a partitioned minority cannot shrink the denominator to suit itself") —
but that protection only engages when you actually set `members`. Leaving it
at the shipped default reopens the exact hole the fix targeted.

**b. Any authenticated node counts as a voter.**

With `members` unset, `is_declared_member()` returns `true` for anyone
(`crates/waf-cluster/src/election/mod.rs:274-276`,
`members.is_empty() || members.contains(node_id)`), so the recount in
`process_result` accepts a grant from *any* node holding a cert that chains to
your cluster CA (`crates/waf-cluster/src/election/mod.rs:609-617`), not just
nodes you actually provisioned. That's a smaller risk than (a) on its own, but
it compounds with anything that lets an unexpected node obtain a valid cluster
certificate (e.g. a leaked or over-broad join token).

### The correct way to declare it

Set `cluster.members` to the exact, fixed list of `node_id`s that make up the
cluster, on **every** node, identically:

```toml
[cluster]
enabled = true
node_id = "node-a"
role    = "auto"
members = ["node-a", "node-b", "node-c"]
```

This must be the full membership you intend to run with — not just the seeds,
not just "the nodes I've deployed so far." `quorum_total()` uses
`members.len()` directly as the fixed denominator
(`crates/waf-cluster/src/node.rs:262-267`), so:

- Adding a node later means updating `members` on every existing node (a
  config change + restart/reload), not just starting the new node and pointing
  it at a seed.
- The list must match on every node. There's no cross-node reconciliation of
  `members` — each node computes quorum against its own configured list.
- `PRXWAF_CLUSTER_MEMBERS` (comma-separated node ids,
  `crates/waf-common/src/config.rs:1230, 1271-1273`) can supply/override this
  via environment instead of TOML if that fits your deployment tooling better —
  same requirement: identical list, every node.

Also set a `join_token` (`cluster.join_token` /
`PRXWAF_CLUSTER_JOIN_TOKEN`) so that, on top of the fixed membership check,
joining nodes must present a token the main validates against the CA key
before being registered as a peer at all
(`crates/waf-cluster/src/transport/server.rs:254-273`).

### Why this matters more than it looks

Nothing about a misconfigured (empty) `members` list produces an error, a
warning at startup, or a degraded-mode banner in the Admin UI. The cluster
works completely normally under normal conditions — normal joins, normal
elections, normal rule sync. The gap only manifests during the one event
clustering exists to survive: a network partition or a main-node failure,
which is precisely when you cannot afford a surprise. Test for it before you
need it (see Section 3).

---

## 3. Verifying you configured this correctly

### Confirm `replicate_ca_key` is off (or deliberately on)

```bash
# Print the effective config; look for [cluster] block
prx-waf cluster status
```

There's no `replicate_ca_key` field surfaced by `cluster status` today, so
verify directly against your deployed config file / environment:

```bash
grep -A2 '\[cluster\]' /path/to/your/config.toml | grep replicate_ca_key
echo "$PRXWAF_CLUSTER_REPLICATE_CA_KEY"
```

If you've deliberately enabled it, confirm the audit trail: main-side logs
should show `ca_key_replicated=true` on the join-accept line for each node you
expect to hold a copy, and `ca_key_replicated=false` for any node that
shouldn't (e.g. a lower-trust worker you scoped out — though per Section 1
you should not be mixing trust tiers here at all).

### Confirm `members` is set and matches across nodes

```bash
# On each node:
prx-waf cluster status   # shows Node ID, Role, Seeds — cross-check against your declared members list
```

Since `cluster status` does not currently print `members` directly, diff the
configured value across nodes instead:

```bash
for host in node-a node-b node-c; do
  echo "== $host =="
  ssh "$host" "grep -A1 members /etc/prx-waf/config.toml"
done
```

All three must print the identical list (same node ids, any order).

### Prove quorum actually holds under partition (the test that matters)

Configuration review only tells you the setting is *present*; it doesn't tell
you the cluster actually survives a partition the way you think it does. Run
a real partition drill in a staging cluster with production-shaped `members`:

1. Bring up a 3+ node cluster with `members` declared identically on all
   nodes.
2. Confirm one Main is elected (`prx-waf cluster status` / Admin UI cluster
   page).
3. Firewall off (not just stop the process on) a minority of nodes — e.g. `iptables`
   drop on UDP 16851 to/from one node in a 3-node cluster — so it can no
   longer reach the majority side, but keep the process running so it still
   evicts its now-unreachable peers.
4. Watch the isolated node's logs. With `members` correctly declared, you
   should see `"Declared cluster membership does not permit single-node
   self-promotion; backing off"` — **not** `"Single-node cluster — claiming
   Main role without election"`. The latter means quorum is not actually fixed
   and you have a split-brain risk in production.
5. Heal the partition and confirm the isolated node rejoins as Worker and
   resyncs rules rather than fighting for Main.

If step 4 shows the isolated node claiming Main, your `members` list is either
missing, inconsistent across nodes, or effectively empty on that node — fix
the config before going to production, not after the first real partition.
