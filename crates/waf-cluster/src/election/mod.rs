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
//!
//! # Byzantine hardening (H-11)
//!
//! `ElectionResult` is a *self-declared* claim: nothing in the message proves
//! that the votes it lists were ever cast. Before H-11 the receiver adopted the
//! announced winner as the authoritative Main after only checking that the
//! sender's mTLS identity matched `elected_id` (H-9), so **any** node holding a
//! valid cluster certificate could announce `ElectionResult { term: u64::MAX,
//! elected_id: self, voter_ids: [] }` and have the whole cluster accept it —
//! and, through the `is_current_main` gate, accept its rule and config pushes.
//!
//! Because the vote grants are unicast to the candidate and carry no per-voter
//! signature, a receiver cannot cryptographically recount the ballot. What it
//! *can* do is check the claim against evidence it produced itself:
//! [`ElectionManager::process_result`] accepts a result only when **this node
//! granted its own vote to `elected_id` in exactly that term**. A node's own
//! vote record is local, unforgeable, and — because a node grants at most one
//! vote per term — a usurper can only ever be recognised by nodes that really
//! did vote for it. A zero-vote or stuffed-ballot takeover is therefore
//! impossible; see `docs/` and the crate report for the residual
//! minority-usurpation case that needs signed vote certificates to close.
//!
//! Term monotonicity is hardened in the same pass: an unverified result never
//! advances the local term, and any single message may advance it by at most
//! [`MAX_TERM_JUMP`], so `term: u64::MAX` can no longer pin the cluster into a
//! permanently un-electable state.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex as ParkingMutex;
use parking_lot::RwLock as ParkingRwLock;
use rand::Rng;
use tokio::time::Duration;
use tracing::{debug, info, warn};
use waf_common::config::NodeRole;

use crate::protocol::{ClusterMessage, ElectionResult, ElectionVote};

/// Maximum number of terms a single inbound message may advance this node's term.
///
/// A node that has been partitioned for a long time can legitimately be many
/// terms behind, so the guard **clamps** instead of rejecting: each message
/// moves us at most this far, and repeated messages from the genuinely-ahead
/// peer let us converge. What it prevents is a single forged message pinning
/// the term at (or near) `u64::MAX`, which would deadlock every future election
/// — `voted_for` is only reset when the term advances, so a saturated term
/// freezes every node's vote forever.
pub const MAX_TERM_JUMP: u64 = 1024;

/// The vote this node granted, together with the term it was granted in.
///
/// Kept as a pair so that acceptance of an `ElectionResult` can be anchored to
/// "did *I* vote for this winner in *this* term" without relying on the term
/// bookkeeping being reset elsewhere (H-11).
#[derive(Debug, Clone)]
struct GrantedVote {
    term: u64,
    candidate_id: String,
}

/// Why a broadcast [`ElectionResult`] was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultRejection {
    /// Term 0 is never the product of an election.
    ZeroTerm,
    /// The announced term is older than ours (classic fencing).
    StaleTerm { result_term: u64, current_term: u64 },
    /// The announced term is ahead of ours: we took no part in that ballot and
    /// therefore hold no evidence that it happened.
    UnobservedTerm { result_term: u64, current_term: u64 },
    /// The winner is not part of the declared cluster membership (M-16).
    IneligibleWinner { elected_id: String },
    /// We did not grant our vote to the announced winner in that term.
    NoLocalVote {
        elected_id: String,
        granted_to: Option<String>,
    },
    /// The announced ballot does not even contain the winner's own vote.
    WinnerNotInBallot { elected_id: String },
    /// The announced ballot does not add up to a quorum.
    QuorumShortfall { counted: usize, quorum_total: usize },
}

impl fmt::Display for ResultRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTerm => write!(f, "election result carries term 0"),
            Self::StaleTerm {
                result_term,
                current_term,
            } => write!(f, "stale term {result_term} < current term {current_term}"),
            Self::UnobservedTerm {
                result_term,
                current_term,
            } => write!(
                f,
                "term {result_term} is ahead of our term {current_term}; this node cast no vote in it"
            ),
            Self::IneligibleWinner { elected_id } => {
                write!(f, "winner '{elected_id}' is not a declared cluster member")
            }
            Self::NoLocalVote { elected_id, granted_to } => write!(
                f,
                "this node did not vote for '{elected_id}' in that term (granted to {})",
                granted_to.as_deref().unwrap_or("nobody")
            ),
            Self::WinnerNotInBallot { elected_id } => {
                write!(f, "announced ballot does not contain the winner '{elected_id}'")
            }
            Self::QuorumShortfall { counted, quorum_total } => write!(
                f,
                "announced ballot holds {counted} eligible vote(s), short of a majority of {quorum_total}"
            ),
        }
    }
}

/// Outcome of validating a broadcast [`ElectionResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultDecision {
    /// The result was corroborated by local evidence; take this role and treat
    /// `elected_id` as the authoritative Main.
    Accepted(NodeRole),
    /// The result could not be corroborated and was ignored. No term, role or
    /// Main-identity state was changed.
    Rejected(ResultRejection),
}

impl ResultDecision {
    /// Returns `true` when the result was accepted.
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

/// Raft-lite election state machine shared by all transport handlers.
///
/// All lock operations are short-lived and never held across `.await` points.
pub struct ElectionManager {
    pub(crate) node_id: String,
    /// Current Raft term (monotonically increasing).
    term: ParkingRwLock<u64>,
    /// The vote granted in the current term (`None` = not yet voted).
    voted_for: ParkingRwLock<Option<GrantedVote>>,
    /// Min/max random election timeout in milliseconds.
    timeout_min_ms: u64,
    timeout_max_ms: u64,
    /// Votes received by THIS node when it is a candidate.
    /// Map: term → set of voter node IDs.
    votes_for_me: ParkingMutex<HashMap<u64, HashSet<String>>>,
    /// Declared cluster membership (M-16). When non-empty, only votes from
    /// listed node ids are counted toward quorum; empty means "count any peer".
    members: ParkingRwLock<HashSet<String>>,
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
            members: ParkingRwLock::new(HashSet::new()),
        }
    }

    /// Declare the fixed cluster membership used for vote eligibility (M-16).
    ///
    /// An empty slice clears the membership constraint (any authenticated peer's
    /// vote counts). Called once at node initialisation from configuration.
    pub fn set_members(&self, member_ids: &[String]) {
        let mut members = self.members.write();
        members.clear();
        members.extend(member_ids.iter().cloned());
    }

    /// Returns `true` if `node_id` may take part in elections (it is in the
    /// declared membership, or membership is unconstrained).
    ///
    /// Applies to both voters and candidates: a node outside the declared
    /// membership neither counts toward quorum nor may be recognised as Main.
    pub fn is_declared_member(&self, node_id: &str) -> bool {
        let members = self.members.read();
        members.is_empty() || members.contains(node_id)
    }

    /// Current term (non-blocking, `parking_lot`).
    pub fn current_term_sync(&self) -> u64 {
        *self.term.read()
    }

    /// Current term (async-compatible wrapper).
    pub fn current_term(&self) -> u64 {
        self.current_term_sync()
    }

    /// Returns a random election timeout within the configured range (ms).
    pub fn election_timeout_ms(&self) -> u64 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.timeout_min_ms..=self.timeout_max_ms.max(self.timeout_min_ms + 1))
    }

    /// Increment the term, clear `voted_for` and `votes_for_me`, then vote for self.
    ///
    /// Returns the new term. Called when this node starts an election.
    pub fn increment_term_and_vote_for_self(&self) -> u64 {
        let new_term = {
            let mut term = self.term.write();
            // Saturating: a term pushed to u64::MAX by a hostile peer must never
            // wrap (wrapping would silently roll the cluster back to term 0) nor
            // panic. MAX_TERM_JUMP makes saturation practically unreachable.
            *term = term.saturating_add(1);
            *term
        };
        // Reset voting state for the new term
        *self.voted_for.write() = Some(GrantedVote {
            term: new_term,
            candidate_id: self.node_id.clone(),
        });
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
        // Grants only count for the term this node is actually standing in, and
        // only while it is standing (it voted for itself). A grant for a term we
        // never ran in — including a fabricated far-future term — is discarded
        // instead of being parked in the ballot map (H-11).
        if term != *self.term.read() {
            return false;
        }
        let standing = matches!(
            self.voted_for.read().as_ref(),
            Some(v) if v.term == term && v.candidate_id == self.node_id
        );
        if !standing {
            debug!(
                node_id = %self.node_id,
                voter = %voter_id,
                term,
                "Ignoring vote grant: this node is not a candidate in that term"
            );
            return false;
        }
        // M-16: a voter outside the declared membership does not count toward quorum.
        if !self.is_declared_member(&voter_id) {
            debug!(
                node_id = %self.node_id,
                voter = %voter_id,
                "Ignoring vote from node outside declared cluster membership"
            );
            return false;
        }
        self.votes_for_me.lock().entry(term).or_default().insert(voter_id)
    }

    /// Number of votes received for `term`.
    pub fn vote_count_for_term(&self, term: u64) -> usize {
        self.votes_for_me.lock().get(&term).map_or(0, HashSet::len)
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
    pub const fn is_majority(votes: usize, total_nodes: usize) -> bool {
        total_nodes > 0 && votes > (total_nodes / 2)
    }

    /// Returns `true` if `incoming_term` is not stale (fencing token check).
    ///
    /// This is a **staleness** test only — `>=` is deliberate, because the
    /// legitimate winner of the election this node just took part in announces
    /// its result at exactly the current term. It is *not* an authorisation
    /// check and must never be used on its own to decide whether a peer may act
    /// as Main; use [`Self::process_result`] for that (H-11).
    pub fn is_valid_term(&self, incoming_term: u64) -> bool {
        incoming_term >= *self.term.read()
    }

    /// Try to update the term if `incoming_term` is larger. Resets `voted_for` on
    /// term advance. Returns the new current term.
    ///
    /// The advance is clamped to [`MAX_TERM_JUMP`] terms per call so a single
    /// forged message cannot pin the term near `u64::MAX`; a peer that is
    /// genuinely far ahead pulls us up over successive messages.
    pub fn advance_term(&self, incoming_term: u64) -> u64 {
        let mut term = self.term.write();
        if incoming_term > *term {
            let ceiling = term.saturating_add(MAX_TERM_JUMP);
            let capped = incoming_term.min(ceiling);
            if capped < incoming_term {
                warn!(
                    node_id = %self.node_id,
                    incoming_term,
                    current_term = *term,
                    clamped_to = capped,
                    "Implausible term jump clamped (possible forged term)"
                );
            }
            *term = capped;
            *self.voted_for.write() = None;
        }
        *term
    }

    /// The candidate this node granted its vote to in `term`, if any.
    ///
    /// This is the local, unforgeable evidence an `ElectionResult` is checked
    /// against (H-11).
    pub fn granted_vote_in_term(&self, term: u64) -> Option<String> {
        self.voted_for
            .read()
            .as_ref()
            .filter(|v| v.term == term)
            .map(|v| v.candidate_id.clone())
    }

    /// Decide whether to grant a vote to `vote.candidate_id`.
    ///
    /// Grants if:
    /// - the candidate is a declared cluster member (M-16), AND
    /// - `vote.term >= current_term` and the term is not an implausible jump, AND
    /// - we have not yet voted for a *different* candidate this term.
    pub fn process_vote(&self, vote: &ElectionVote) -> anyhow::Result<bool> {
        // M-16: only declared members may stand for election. This also bounds
        // who can drive our term forward.
        if !self.is_declared_member(&vote.candidate_id) {
            debug!(
                node_id = %self.node_id,
                candidate = %vote.candidate_id,
                "Denied vote — candidate is not a declared cluster member"
            );
            return Ok(false);
        }
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
            // Advance our term (clamped); a clamped jump means the request is
            // implausibly far ahead — deny this round and let the candidate
            // pull us the rest of the way with its next request.
            let reached = self.advance_term(vote.term);
            if reached < vote.term {
                return Ok(false);
            }
        }
        let mut voted_for = self.voted_for.write();
        let can_vote = voted_for
            .as_ref()
            .is_none_or(|v| v.term < vote.term || v.candidate_id == vote.candidate_id);
        if can_vote {
            *voted_for = Some(GrantedVote {
                term: vote.term,
                candidate_id: vote.candidate_id.clone(),
            });
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
            already_voted_for = voted_for.as_ref().map_or("?", |v| v.candidate_id.as_str()),
            "Denied vote — already voted for different candidate"
        );
        Ok(false)
    }

    /// Validate a broadcast `ElectionResult` and decide the resulting role.
    ///
    /// # Security (H-11)
    ///
    /// `result` is an unauthenticated claim about a ballot this node cannot
    /// recount, so it is corroborated against local evidence instead:
    ///
    /// 1. the term must be non-zero and **exactly** the term this node is in —
    ///    a stale term is fenced off, and a term we never reached is a ballot we
    ///    did not take part in;
    /// 2. the winner must be a declared cluster member (M-16);
    /// 3. **this node must itself have granted its vote to the winner in that
    ///    term** — the anchor. A node grants at most one vote per term, so a
    ///    node that never voted for the sender can never be talked into
    ///    recognising it, no matter what `voter_ids` claims;
    /// 4. the announced ballot must contain the winner and, counting only
    ///    declared members plus this node's own (known-genuine) vote, must reach
    ///    a majority of `quorum_total`.
    ///
    /// A rejected result changes **nothing**: not the term, not the role, not
    /// the recorded Main identity. In particular the term is never advanced from
    /// an unverified result, which is what closes the `term: u64::MAX` lockout.
    ///
    /// `quorum_total` is the cluster size quorum is measured against — see
    /// [`crate::node::NodeState::quorum_total`].
    pub fn process_result(&self, result: &ElectionResult, quorum_total: usize) -> ResultDecision {
        if result.term == 0 {
            return ResultDecision::Rejected(ResultRejection::ZeroTerm);
        }
        let current_term = self.current_term_sync();
        if result.term < current_term {
            return ResultDecision::Rejected(ResultRejection::StaleTerm {
                result_term: result.term,
                current_term,
            });
        }
        if result.term > current_term {
            return ResultDecision::Rejected(ResultRejection::UnobservedTerm {
                result_term: result.term,
                current_term,
            });
        }
        if !self.is_declared_member(&result.elected_id) {
            return ResultDecision::Rejected(ResultRejection::IneligibleWinner {
                elected_id: result.elected_id.clone(),
            });
        }
        let granted_to = self.granted_vote_in_term(result.term);
        if granted_to.as_deref() != Some(result.elected_id.as_str()) {
            return ResultDecision::Rejected(ResultRejection::NoLocalVote {
                elected_id: result.elected_id.clone(),
                granted_to,
            });
        }
        if !result.voter_ids.contains(&result.elected_id) {
            return ResultDecision::Rejected(ResultRejection::WinnerNotInBallot {
                elected_id: result.elected_id.clone(),
            });
        }
        // Count distinct declared members only. Our own vote is added
        // unconditionally: step 3 proved we cast it, whether or not the winner
        // bothered to list us.
        let mut ballot: HashSet<&str> = result
            .voter_ids
            .iter()
            .map(String::as_str)
            .filter(|id| self.is_declared_member(id))
            .collect();
        ballot.insert(self.node_id.as_str());
        if !Self::is_majority(ballot.len(), quorum_total) {
            return ResultDecision::Rejected(ResultRejection::QuorumShortfall {
                counted: ballot.len(),
                quorum_total,
            });
        }

        if result.elected_id == self.node_id {
            info!(
                node_id = %self.node_id,
                term = result.term,
                voters = ?result.voter_ids,
                "Elected as cluster main"
            );
            ResultDecision::Accepted(NodeRole::Main)
        } else {
            info!(
                node_id = %self.node_id,
                elected = %result.elected_id,
                term = result.term,
                "Stepping down — new main elected"
            );
            ResultDecision::Accepted(NodeRole::Worker)
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

        // M-16: quorum is based on the declared membership size when configured,
        // otherwise the live peer view (peers + self).
        let total_nodes = node_state.quorum_total().await;

        // Single-node cluster: win immediately without a vote round — but only
        // when this node is genuinely the sole participant. With a declared
        // membership expecting more nodes, a minority must not self-promote
        // (split-brain prevention).
        if total_nodes <= 1 {
            let members = &node_state.config.members;
            let sole_declared_member =
                members.is_empty() || (members.len() == 1 && members.contains(&node_state.node_id));
            if sole_declared_member {
                info!(
                    node_id = %node_state.node_id,
                    "Single-node cluster — claiming Main role without election"
                );
                node_state.promote_to_main().await;
            } else {
                warn!(
                    node_id = %node_state.node_id,
                    "Declared cluster membership does not permit single-node self-promotion; backing off"
                );
                node_state.demote_to_worker().await;
            }
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
        node_state.broadcast(&vote_req);

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
            node_state.broadcast(&result_msg);

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
    let main_node_id = peers
        .iter()
        .find(|p| p.role == NodeRole::Main)
        .map(|p| p.node_id.clone());
    let has_peers = !peers.is_empty();
    drop(peers);
    main_node_id.map_or_else(
        // No main known — start election only if we have peers.
        || has_peers,
        |node_id| {
            let tracker = node_state.heartbeat_tracker.lock();
            tracker.is_peer_dead(&node_id, now_ms)
        },
    )
}

#[allow(clippy::cast_possible_truncation)]
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn vote_from_non_member_is_not_counted() {
        let em = ElectionManager::new("n1".to_string(), 150, 300);
        em.set_members(&ids(&["n1", "n2", "n3"]));
        em.increment_term_and_vote_for_self();
        assert_eq!(em.vote_count_for_term(1), 1, "self vote only");
        assert!(
            !em.record_vote_for_me(1, "outsider".to_string()),
            "vote from a non-member must be rejected"
        );
        assert_eq!(em.vote_count_for_term(1), 1, "outsider must not inflate count");
        assert!(em.record_vote_for_me(1, "n2".to_string()), "member vote counts");
        assert_eq!(em.vote_count_for_term(1), 2);
    }

    #[test]
    fn empty_membership_counts_any_authenticated_voter() {
        let em = ElectionManager::new("n1".to_string(), 150, 300);
        em.increment_term_and_vote_for_self();
        assert!(em.record_vote_for_me(1, "any-peer".to_string()));
        assert_eq!(em.vote_count_for_term(1), 2);
    }

    #[test]
    fn minority_of_declared_members_is_not_majority() {
        // 5 declared members: a 2-node partition can never reach majority.
        assert!(!ElectionManager::is_majority(2, 5));
        assert!(ElectionManager::is_majority(3, 5));
    }
}
