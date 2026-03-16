//! Raft-lite election state machine.
//!
//! Implements term tracking, vote granting, and role transitions.
//!
//! # Election flow
//!
//! 1. Worker waits a random timeout (150–300 ms).
//! 2. If no heartbeat from the main within that window (phi-accrual declares it
//!    dead), the worker transitions to **Candidate**.
//! 3. Candidate increments term, votes for itself, broadcasts
//!    `ElectionVote{candidate_id: self, voter_id: None}` to all peers.
//! 4. Each peer that grants the vote echoes the `ElectionVote` back with
//!    `voter_id: Some(peer_id)`.
//! 5. Candidate counts incoming echoes; when it reaches N/2+1 (majority of
//!    total cluster size) it promotes itself to **Main** and broadcasts
//!    `ElectionResult`.
//! 6. All nodes that receive `ElectionResult` update their term and role.
//!
//! # Split-brain prevention
//!
//! - Votes are only counted for the candidate's current term; stale-term votes
//!   are discarded.
//! - A node only wins if `vote_count >= (total_nodes / 2) + 1`.
//! - `ElectionResult` with `term < current_term` is silently ignored (fencing).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex as ParkingMutex;
use parking_lot::RwLock as ParkingRwLock;
use rand::Rng;
use tokio::time::Duration;
use tracing::{debug, info, warn};
use waf_common::config::NodeRole;

use crate::protocol::{ClusterMessage, ElectionResult, ElectionVote};

/// Raft-lite election state machine shared by all transport handlers.
///
/// All lock operations are short-lived and never held across `.await` points.
pub struct ElectionManager {
    pub(crate) node_id: String,
    /// Current Raft term (monotonically increasing).
    term: ParkingRwLock<u64>,
    /// Which candidate we have voted for in the current term (`None` = not yet).
    voted_for: ParkingRwLock<Option<String>>,
    /// Min/max random election timeout in milliseconds.
    timeout_min_ms: u64,
    timeout_max_ms: u64,
    /// Votes received by THIS node when it is a candidate.
    /// Map: term → set of voter node IDs.
    votes_for_me: ParkingMutex<HashMap<u64, HashSet<String>>>,
}

impl ElectionManager {
    /// Create a new election manager for `node_id`.
    pub fn new(node_id: String, timeout_min_ms: u64, timeout_max_ms: u64) -> Self {
        Self {
            node_id,
            term: ParkingRwLock::new(0),
            voted_for: ParkingRwLock::new(None),
            timeout_min_ms,
            timeout_max_ms,
            votes_for_me: ParkingMutex::new(HashMap::new()),
        }
    }

    /// Current term (non-blocking, parking_lot).
    pub fn current_term_sync(&self) -> u64 {
        *self.term.read()
    }

    /// Current term (async-compatible wrapper).
    pub async fn current_term(&self) -> u64 {
        self.current_term_sync()
    }

    /// Returns a random election timeout within the configured range (ms).
    pub fn election_timeout_ms(&self) -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.timeout_min_ms..=self.timeout_max_ms.max(self.timeout_min_ms + 1))
    }

    /// Increment the term, clear voted_for and votes_for_me, then vote for self.
    ///
    /// Returns the new term. Called when this node starts an election.
    pub fn increment_term_and_vote_for_self(&self) -> u64 {
        let mut term = self.term.write();
        *term += 1;
        let new_term = *term;
        // Reset voting state for the new term
        *self.voted_for.write() = Some(self.node_id.clone());
        // Keep only the new term's vote bucket (remove older)
        let mut votes = self.votes_for_me.lock();
        votes.retain(|&t, _| t >= new_term);
        votes.entry(new_term).or_default().insert(self.node_id.clone());
        new_term
    }

    /// Record a vote for this node from `voter_id` for `term`.
    ///
    /// Returns `true` if this is a new (non-duplicate) vote.
    pub fn record_vote_for_me(&self, term: u64, voter_id: String) -> bool {
        // Only count votes for the current term
        if term < *self.term.read() {
            return false;
        }
        self.votes_for_me.lock().entry(term).or_default().insert(voter_id)
    }

    /// Number of votes received for `term`.
    pub fn vote_count_for_term(&self, term: u64) -> usize {
        self.votes_for_me
            .lock()
            .get(&term)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Collect voter IDs for `term` (used when broadcasting `ElectionResult`).
    pub fn voter_ids_for_term(&self, term: u64) -> Vec<String> {
        self.votes_for_me
            .lock()
            .get(&term)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns `true` if `votes` is a majority of `total_nodes`.
    pub fn is_majority(votes: usize, total_nodes: usize) -> bool {
        total_nodes > 0 && votes > (total_nodes / 2)
    }

    /// Returns `true` if `incoming_term` is not stale (fencing token check).
    pub fn is_valid_term(&self, incoming_term: u64) -> bool {
        incoming_term >= *self.term.read()
    }

    /// Try to update the term if `incoming_term` is larger. Resets voted_for on
    /// term advance. Returns the new current term.
    pub fn advance_term(&self, incoming_term: u64) -> u64 {
        let mut term = self.term.write();
        if incoming_term > *term {
            *term = incoming_term;
            *self.voted_for.write() = None;
        }
        *term
    }

    /// Decide whether to grant a vote to `vote.candidate_id`.
    ///
    /// Grants if:
    /// - `vote.term >= current_term` (not stale), AND
    /// - We have not yet voted for a *different* candidate this term.
    pub async fn process_vote(&self, vote: &ElectionVote) -> anyhow::Result<bool> {
        let current_term = *self.term.read();
        if vote.term < current_term {
            debug!(
                node_id = %self.node_id,
                candidate = %vote.candidate_id,
                vote_term = vote.term,
                current_term,
                "Rejecting stale vote request"
            );
            return Ok(false);
        }
        if vote.term > current_term {
            // Advance our term; clear prior vote
            *self.term.write() = vote.term;
            *self.voted_for.write() = None;
        }
        let mut voted_for = self.voted_for.write();
        let can_vote =
            voted_for.is_none() || voted_for.as_deref() == Some(vote.candidate_id.as_str());
        if can_vote {
            *voted_for = Some(vote.candidate_id.clone());
            info!(
                node_id = %self.node_id,
                candidate = %vote.candidate_id,
                term = vote.term,
                "Granted election vote"
            );
            return Ok(true);
        }
        debug!(
            node_id = %self.node_id,
            candidate = %vote.candidate_id,
            already_voted_for = voted_for.as_deref().unwrap_or("?"),
            "Denied vote — already voted for different candidate"
        );
        Ok(false)
    }

    /// Process an `ElectionResult`.
    ///
    /// Returns the `NodeRole` this node should transition to:
    /// - `Main` if we are the elected leader.
    /// - `Worker` otherwise.
    pub async fn process_result(&self, result: &ElectionResult) -> anyhow::Result<NodeRole> {
        // Fencing: reject stale-term leaders
        if !self.is_valid_term(result.term) {
            warn!(
                node_id = %self.node_id,
                result_term = result.term,
                current_term = self.current_term_sync(),
                "Rejected stale ElectionResult (split-brain prevention)"
            );
            return Ok(NodeRole::Worker);
        }
        self.advance_term(result.term);
        if result.elected_id == self.node_id {
            info!(
                node_id = %self.node_id,
                term = result.term,
                voters = ?result.voter_ids,
                "Elected as cluster main"
            );
            Ok(NodeRole::Main)
        } else {
            info!(
                node_id = %self.node_id,
                elected = %result.elected_id,
                term = result.term,
                "Stepping down — new main elected"
            );
            Ok(NodeRole::Worker)
        }
    }
}

// ─── Background election loop ─────────────────────────────────────────────────

/// Long-running election loop.
///
/// This task runs for the lifetime of the cluster node.  It:
/// 1. Monitors the phi-accrual detector for main node failure.
/// 2. Starts a Raft-lite election when the main is declared dead.
/// 3. Promotes this node to Main if it wins the election.
/// 4. Broadcasts `ElectionResult` so all peers can update their state.
///
/// Runs until the tokio task is cancelled.
pub async fn run_election_loop(node_state: Arc<crate::node::NodeState>) {
    loop {
        // Only workers/candidates participate in elections; mains just sleep.
        let role = node_state.current_role().await;
        if role == NodeRole::Main {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        // Wait for a random election timeout.
        let timeout_ms = node_state.election.election_timeout_ms();
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;

        // Detect whether the current main is dead.
        let now_ms = unix_ms();
        if !check_main_is_dead(&node_state, now_ms).await {
            continue;
        }

        // ── Start election ──────────────────────────────────────────────────

        // Count total known cluster nodes (peers + self).
        let total_nodes = node_state.total_nodes().await;

        // Single-node cluster: win immediately without a vote round.
        if total_nodes <= 1 {
            info!(
                node_id = %node_state.node_id,
                "Single-node cluster — claiming Main role without election"
            );
            node_state.promote_to_main().await;
            continue;
        }

        // Transition to Candidate.
        node_state.transition_to(NodeRole::Candidate).await;

        let new_term = node_state.election.increment_term_and_vote_for_self();

        info!(
            node_id = %node_state.node_id,
            term = new_term,
            total_nodes,
            "Starting election"
        );

        // Broadcast vote request to all peers.
        let vote_req = ClusterMessage::ElectionVote(ElectionVote {
            term: new_term,
            candidate_id: node_state.node_id.clone(),
            last_log_index: *node_state.rules_version.read().await,
            voter_id: None,
        });
        node_state.broadcast(vote_req).await;

        // Wait another timeout for vote grants to arrive.
        let wait_ms = node_state.election.election_timeout_ms();
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;

        // Check whether we accumulated a majority.
        let vote_count = node_state.election.vote_count_for_term(new_term);
        if ElectionManager::is_majority(vote_count, total_nodes) {
            node_state.promote_to_main().await;

            let voter_ids = node_state.election.voter_ids_for_term(new_term);
            let result_msg = ClusterMessage::ElectionResult(ElectionResult {
                term: new_term,
                elected_id: node_state.node_id.clone(),
                voter_ids,
            });
            node_state.broadcast(result_msg).await;

            info!(
                node_id = %node_state.node_id,
                term = new_term,
                votes = vote_count,
                total = total_nodes,
                "Won election — promoted to Main"
            );
        } else {
            // Lost or split vote — step back down to Worker and back off.
            warn!(
                node_id = %node_state.node_id,
                term = new_term,
                votes = vote_count,
                needed = (total_nodes / 2) + 1,
                "Election failed: insufficient votes — backing off"
            );
            node_state.demote_to_worker().await;
        }
    }
}

/// Returns `true` if the currently known main node should be considered dead.
///
/// - If a peer with role `Main` is tracked and phi-accrual declares it dead → true.
/// - If no main peer is known yet and we have at least one peer → true (bootstrap).
/// - If no peers at all → false (stay quiet; handled by single-node path).
async fn check_main_is_dead(node_state: &crate::node::NodeState, now_ms: u64) -> bool {
    let peers = node_state.peers.read().await;
    let main_peer = peers.iter().find(|p| p.role == NodeRole::Main);
    match main_peer {
        Some(peer) => {
            let tracker = node_state.heartbeat_tracker.lock();
            tracker.is_peer_dead(&peer.node_id, now_ms)
        }
        None => {
            // No main known — start election only if we have peers.
            !peers.is_empty()
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
