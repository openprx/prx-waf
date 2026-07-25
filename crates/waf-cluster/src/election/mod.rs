//! Raft-lite election state machine.
//!
//! Implements term tracking, vote granting, and role transitions.
//!
//! # Election flow
//!
//! 1. Worker waits a random timeout (150–300 ms).
//! 2. If no heartbeat from the main within that window (phi-accrual declares it
//!    dead), the worker transitions to **Candidate**.
//! 3. Candidate increments term, signs a grant for itself, broadcasts
//!    `ElectionVote{candidate_id: self, voter_id: None}` to all peers.
//! 4. Each peer that grants the vote echoes the `ElectionVote` back with
//!    `voter_id: Some(peer_id)` **and** a `SignedGrant` over `(term, candidate)`.
//! 5. Candidate verifies and counts incoming grants; when it reaches N/2+1
//!    (majority of total cluster size) it promotes itself to **Main** and
//!    broadcasts `ElectionResult` carrying every grant it collected.
//! 6. Every node that receives `ElectionResult` recounts those grants for itself
//!    and, if they are a majority, updates its term and role.
//!
//! # Split-brain prevention
//!
//! - Votes are only counted for the candidate's current term; stale-term votes
//!   are discarded.
//! - A node only wins if `vote_count >= (total_nodes / 2) + 1`.
//! - `ElectionResult` with `term < current_term` is silently ignored (fencing).
//! - Quorum is measured against the declared `members` list when configured, so
//!   a partitioned minority cannot shrink the denominator to suit itself.
//!
//! # Byzantine hardening (H-11 → H-12)
//!
//! `ElectionResult` used to be a *self-declared* claim: nothing in the message
//! proved that the votes it listed were ever cast. Before H-11 the receiver
//! adopted the announced winner as the authoritative Main after only checking
//! that the sender's mTLS identity matched `elected_id` (H-9), so **any** node
//! holding a valid cluster certificate could announce `ElectionResult { term:
//! u64::MAX, elected_id: self, voter_ids: [] }` and have the whole cluster
//! accept it — and, through the `is_current_main` gate, accept its rule and
//! config pushes.
//!
//! H-11 anchored acceptance to the one piece of unforgeable local evidence a
//! receiver had: its own vote in that term. That stopped zero-vote and
//! stuffed-ballot takeovers, but it could not stop a candidate that had really
//! collected a *minority* of votes from fabricating the rest of the ballot — the
//! nodes that had voted for it saw their own anchor hold and could not check the
//! other names. It also cost liveness, because a node that had voted for the
//! losing candidate could not corroborate the genuine winner either.
//!
//! H-12 removes the guesswork: every vote grant now carries a
//! [`crate::protocol::SignedGrant`], so `ElectionResult.grants` is a **quorum
//! certificate** that any holder of the cluster CA certificate can recount from
//! first principles — chain-validate each voter certificate, take the voter's
//! `node_id` from its SAN, verify the signature over `(term, elected_id)`, count
//! distinct declared members. [`ElectionManager::process_result`] accepts only
//! when that count is a majority. Forging one entry requires a voter's private
//! key; forging a quorum requires a majority of them. With the ballot verifiable
//! the local-vote anchor is gone, and with it the liveness debt it created.
//!
//! Term monotonicity is unchanged: any single message may advance the term by at
//! most [`MAX_TERM_JUMP`], and no unverified result advances it at all, so
//! `term: u64::MAX` cannot pin the cluster into a permanently un-electable
//! state. A node grants at most one vote per term (`voted_for`), which is what
//! makes two conflicting quorum certificates for one term impossible.

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

use crate::crypto::vote::ClusterIdentity;
use crate::protocol::{ClusterMessage, ElectionResult, ElectionVote, SignedGrant};

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

/// Fallback cap on the number of grants examined in one announced ballot.
///
/// Every entry costs a certificate path validation and a signature check, so an
/// authenticated-but-hostile peer must not be able to hand us an unbounded list.
/// When a `members` list is configured the real bound is its size — a legitimate
/// ballot cannot exceed it — and this constant only applies to clusters running
/// without a declared membership. No real cluster fields this many voters.
pub const MAX_BALLOT_GRANTS: usize = 512;

/// The vote this node granted, together with the term it was granted in.
///
/// Enforces the one-vote-per-term rule that makes two conflicting quorum
/// certificates for the same term impossible: this node signs a grant for at
/// most one candidate per term.
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
    /// The announced term is further ahead than a single message may carry us.
    ImplausibleTerm { result_term: u64, ceiling: u64 },
    /// The winner is not part of the declared cluster membership (M-16).
    IneligibleWinner { elected_id: String },
    /// The ballot carries more entries than we are willing to verify.
    BallotTooLarge { grants: usize, limit: usize },
    /// No cluster identity is attached, so no grant can be verified. Fail closed
    /// rather than trust an unverifiable ballot.
    NoClusterIdentity,
    /// The announced ballot holds no valid grant from the winner itself.
    WinnerNotInBallot { elected_id: String },
    /// The verified grants do not add up to a quorum.
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
            Self::ImplausibleTerm { result_term, ceiling } => write!(
                f,
                "term {result_term} is beyond the per-message ceiling {ceiling}; catching up through the join handshake instead"
            ),
            Self::IneligibleWinner { elected_id } => {
                write!(f, "winner '{elected_id}' is not a declared cluster member")
            }
            Self::BallotTooLarge { grants, limit } => {
                write!(f, "announced ballot holds {grants} grants, over the {limit} limit")
            }
            Self::NoClusterIdentity => write!(
                f,
                "no cluster certificate identity is attached; vote grants cannot be verified"
            ),
            Self::WinnerNotInBallot { elected_id } => {
                write!(
                    f,
                    "announced ballot holds no valid grant from the winner '{elected_id}'"
                )
            }
            Self::QuorumShortfall { counted, quorum_total } => write!(
                f,
                "announced ballot holds {counted} verified vote(s), short of a majority of {quorum_total}"
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
    /// Verified grants received by THIS node when it is a candidate.
    /// Map: term → voter node id → that voter's signed grant.
    votes_for_me: ParkingMutex<HashMap<u64, HashMap<String, SignedGrant>>>,
    /// Declared cluster membership (M-16). When non-empty, only votes from
    /// listed node ids are counted toward quorum; empty means "count any peer".
    members: ParkingRwLock<HashSet<String>>,
    /// Certificate identity used to sign this node's grants and to verify
    /// everybody else's (H-12). Attached once the transport certificates are
    /// available; until then no ballot can be produced or accepted.
    identity: ParkingRwLock<Option<Arc<ClusterIdentity>>>,
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
            identity: ParkingRwLock::new(None),
        }
    }

    /// Attach the certificate identity used to sign and verify vote grants.
    ///
    /// Called once at startup, after the node's certificate material has been
    /// generated or loaded. Elections cannot complete before this is attached.
    pub fn attach_identity(&self, identity: Arc<ClusterIdentity>) {
        if identity.node_id() != self.node_id {
            warn!(
                node_id = %self.node_id,
                certificate_id = %identity.node_id(),
                "Cluster certificate names a different node than the configured node_id; \
                 peers will attribute this node's votes to the certificate identity"
            );
        }
        *self.identity.write() = Some(identity);
    }

    /// Clone the attached certificate identity, if any.
    fn identity(&self) -> Option<Arc<ClusterIdentity>> {
        self.identity.read().clone()
    }

    /// Sign a vote grant for `candidate_id` in `term`.
    ///
    /// Returns `None` when no certificate identity is attached.
    pub fn sign_grant(&self, term: u64, candidate_id: &str) -> Option<SignedGrant> {
        self.identity().map(|id| id.sign_grant(term, candidate_id))
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

    /// Size of the declared cluster membership, or `None` when unconstrained.
    fn declared_member_count(&self) -> Option<usize> {
        let members = self.members.read();
        (!members.is_empty()).then(|| members.len())
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
    /// Returns the new term. Called when this node starts an election. The
    /// self-vote is recorded as a signed grant like any other, so the ballot this
    /// node later announces is verifiable end to end. Without an attached
    /// identity the self-vote cannot be signed and the election will simply not
    /// reach a verifiable quorum — the fail-closed outcome.
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
        // Sign before taking the ballot lock: verification and signing are pure
        // and must not be done while holding a lock the transport also wants.
        let self_grant = self.sign_grant(new_term, &self.node_id);
        if self_grant.is_none() {
            warn!(
                node_id = %self.node_id,
                term = new_term,
                "Cannot sign this node's own vote: no cluster certificate identity attached"
            );
        }
        // Keep only the new term's vote bucket (remove older)
        let mut votes = self.votes_for_me.lock();
        votes.retain(|&t, _| t >= new_term);
        if let Some(grant) = self_grant {
            votes.entry(new_term).or_default().insert(self.node_id.clone(), grant);
        }
        drop(votes);
        new_term
    }

    /// Record a signed vote grant addressed to this node as candidate.
    ///
    /// `authenticated_voter` is the identity proven by the peer's mTLS
    /// certificate (H-9). The grant's own signature must resolve to the same
    /// node, so a peer can neither vote twice under different names nor relay
    /// somebody else's grant as its own.
    ///
    /// Returns `true` if this is a new (non-duplicate) verified vote.
    pub fn record_grant(&self, term: u64, grant: &SignedGrant, authenticated_voter: &str) -> bool {
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
                voter = %authenticated_voter,
                term,
                "Ignoring vote grant: this node is not a candidate in that term"
            );
            return false;
        }
        // M-16: a voter outside the declared membership does not count toward quorum.
        if !self.is_declared_member(authenticated_voter) {
            debug!(
                node_id = %self.node_id,
                voter = %authenticated_voter,
                "Ignoring vote from node outside declared cluster membership"
            );
            return false;
        }
        let Some(identity) = self.identity() else {
            warn!(
                node_id = %self.node_id,
                "Ignoring vote grant: no cluster certificate identity attached to verify it"
            );
            return false;
        };
        // H-12: verify before storing. A grant we cannot verify would poison the
        // ballot we later broadcast — and would make this node believe it had
        // won an election that no peer will accept.
        let signer = match identity.verify_grant(grant, term, &self.node_id) {
            Ok(signer) => signer,
            Err(e) => {
                warn!(
                    node_id = %self.node_id,
                    voter = %authenticated_voter,
                    term,
                    "Discarding unverifiable vote grant: {e}"
                );
                return false;
            }
        };
        if signer != authenticated_voter {
            warn!(
                node_id = %self.node_id,
                signer = %signer,
                authenticated = %authenticated_voter,
                "Discarding vote grant: signer does not match the peer certificate identity"
            );
            return false;
        }
        self.votes_for_me
            .lock()
            .entry(term)
            .or_default()
            .insert(signer, grant.clone())
            .is_none()
    }

    /// Number of verified votes received for `term`.
    pub fn vote_count_for_term(&self, term: u64) -> usize {
        self.votes_for_me.lock().get(&term).map_or(0, HashMap::len)
    }

    /// Collect the verified voter IDs for `term` (observability / diagnostics).
    pub fn voter_ids_for_term(&self, term: u64) -> Vec<String> {
        self.votes_for_me
            .lock()
            .get(&term)
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Collect the quorum certificate for `term` — every verified grant this
    /// node holds, used when broadcasting its `ElectionResult`.
    pub fn grants_for_term(&self, term: u64) -> Vec<SignedGrant> {
        self.votes_for_me
            .lock()
            .get(&term)
            .map(|s| s.values().cloned().collect())
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
    /// as Main; use [`Self::process_result`] for that (H-12).
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
    /// # Security (H-12)
    ///
    /// `result.grants` is a quorum certificate, so the ballot is **recounted**
    /// rather than believed:
    ///
    /// 1. the term must be non-zero, not stale, and not further ahead than a
    ///    single message may carry us ([`MAX_TERM_JUMP`]);
    /// 2. the winner must be a declared cluster member (M-16);
    /// 3. the ballot must be of a sane size, and every grant in it must
    ///    chain-validate to the cluster CA, resolve (via its certificate SAN) to
    ///    a distinct declared member, and carry a signature over exactly this
    ///    `(term, elected_id)` pair — anything else is dropped silently;
    /// 4. the winner's own grant must be among them, and the distinct verified
    ///    voters must be a majority of `quorum_total`.
    ///
    /// Nothing here consults this node's own vote. It does not need to: a
    /// majority of signatures is stronger evidence than one local record, and
    /// dropping the local anchor is what lets a node that voted for the losing
    /// candidate still recognise the genuine winner.
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
        let ceiling = current_term.saturating_add(MAX_TERM_JUMP);
        if result.term > ceiling {
            return ResultDecision::Rejected(ResultRejection::ImplausibleTerm {
                result_term: result.term,
                ceiling,
            });
        }
        if !self.is_declared_member(&result.elected_id) {
            return ResultDecision::Rejected(ResultRejection::IneligibleWinner {
                elected_id: result.elected_id.clone(),
            });
        }
        // Bound the verification work *before* doing any of it. With a declared
        // membership the bound is exact — a legitimate ballot can never hold more
        // grants than there are members — which is one more reason to configure
        // `members`. Without one we fall back to the blunt global cap, since the
        // live peer view may legitimately be smaller than the sender's.
        let limit = self.declared_member_count().unwrap_or(MAX_BALLOT_GRANTS);
        if result.grants.len() > limit {
            return ResultDecision::Rejected(ResultRejection::BallotTooLarge {
                grants: result.grants.len(),
                limit,
            });
        }
        let Some(identity) = self.identity() else {
            return ResultDecision::Rejected(ResultRejection::NoClusterIdentity);
        };

        // Recount: only distinct declared members whose signature really covers
        // this term and this winner are counted. Our own vote gets no special
        // treatment — if we granted it, our signed grant is in the ballot.
        let mut ballot: HashSet<String> = HashSet::new();
        for grant in &result.grants {
            match identity.verify_grant(grant, result.term, &result.elected_id) {
                Ok(voter_id) if self.is_declared_member(&voter_id) => {
                    ballot.insert(voter_id);
                }
                Ok(voter_id) => debug!(
                    node_id = %self.node_id,
                    voter = %voter_id,
                    "Discarding grant from a node outside the declared cluster membership"
                ),
                Err(e) => debug!(
                    node_id = %self.node_id,
                    elected = %result.elected_id,
                    term = result.term,
                    "Discarding unverifiable grant from announced ballot: {e}"
                ),
            }
        }
        if !ballot.contains(&result.elected_id) {
            return ResultDecision::Rejected(ResultRejection::WinnerNotInBallot {
                elected_id: result.elected_id.clone(),
            });
        }
        if !Self::is_majority(ballot.len(), quorum_total) {
            return ResultDecision::Rejected(ResultRejection::QuorumShortfall {
                counted: ballot.len(),
                quorum_total,
            });
        }

        // Verified: adopt the winner's term and drop stale candidacy state.
        self.advance_term(result.term);
        self.votes_for_me.lock().retain(|&t, _| t >= result.term);

        if result.elected_id == self.node_id {
            info!(
                node_id = %self.node_id,
                term = result.term,
                voters = ballot.len(),
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
            grant: None,
        });
        node_state.broadcast(&vote_req);

        // Wait another timeout for vote grants to arrive.
        let wait_ms = node_state.election.election_timeout_ms();
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;

        // Check whether we accumulated a majority.
        let vote_count = node_state.election.vote_count_for_term(new_term);
        if ElectionManager::is_majority(vote_count, total_nodes) {
            node_state.promote_to_main().await;

            // The ballot travels with the announcement: every peer recounts it
            // from the signatures instead of taking our word for it (H-12).
            let grants = node_state.election.grants_for_term(new_term);
            let result_msg = ClusterMessage::ElectionResult(ElectionResult {
                term: new_term,
                elected_id: node_state.node_id.clone(),
                grants,
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::TestPki;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// An election manager wired to a freshly minted identity under `pki`.
    fn manager(node_id: &str, pki: &TestPki) -> ElectionManager {
        let em = ElectionManager::new(node_id.to_string(), 150, 300);
        em.attach_identity(pki.identity(node_id));
        em
    }

    #[test]
    fn vote_from_non_member_is_not_counted() {
        let pki = TestPki::new();
        let em = manager("n1", &pki);
        em.set_members(&ids(&["n1", "n2", "n3"]));
        em.increment_term_and_vote_for_self();
        assert_eq!(em.vote_count_for_term(1), 1, "self vote only");

        let outsider = pki.grant("outsider", 1, "n1");
        assert!(
            !em.record_grant(1, &outsider, "outsider"),
            "vote from a non-member must be rejected"
        );
        assert_eq!(em.vote_count_for_term(1), 1, "outsider must not inflate count");

        let n2 = pki.grant("n2", 1, "n1");
        assert!(em.record_grant(1, &n2, "n2"), "member vote counts");
        assert_eq!(em.vote_count_for_term(1), 2);
        assert!(!em.record_grant(1, &n2, "n2"), "the same voter counts only once");
        assert_eq!(em.vote_count_for_term(1), 2);
    }

    #[test]
    fn empty_membership_counts_any_authenticated_voter() {
        let pki = TestPki::new();
        let em = manager("n1", &pki);
        em.increment_term_and_vote_for_self();
        let grant = pki.grant("any-peer", 1, "n1");
        assert!(em.record_grant(1, &grant, "any-peer"));
        assert_eq!(em.vote_count_for_term(1), 2);
    }

    /// A peer cannot relay another node's grant as if it were its own: the
    /// signer recovered from the certificate must be the authenticated peer.
    #[test]
    fn relayed_grant_attributed_to_the_wrong_peer_is_refused() {
        let pki = TestPki::new();
        let em = manager("n1", &pki);
        em.increment_term_and_vote_for_self();
        let grant = pki.grant("peer-a", 1, "n1");
        assert!(
            !em.record_grant(1, &grant, "peer-b"),
            "peer-b must not be able to submit peer-a's grant"
        );
        assert_eq!(em.vote_count_for_term(1), 1);
    }

    /// A grant signed under a foreign CA never enters the ballot.
    #[test]
    fn grant_from_a_foreign_ca_is_refused() {
        let pki = TestPki::new();
        let foreign = TestPki::new();
        let em = manager("n1", &pki);
        em.increment_term_and_vote_for_self();
        let grant = foreign.grant("peer-a", 1, "n1");
        assert!(!em.record_grant(1, &grant, "peer-a"));
        assert_eq!(em.vote_count_for_term(1), 1);
    }

    #[test]
    fn minority_of_declared_members_is_not_majority() {
        // 5 declared members: a 2-node partition can never reach majority.
        assert!(!ElectionManager::is_majority(2, 5));
        assert!(ElectionManager::is_majority(3, 5));
    }

    /// Without an attached certificate identity a node can neither sign its own
    /// vote nor accept anybody's ballot — the fail-closed posture.
    #[test]
    fn without_an_identity_nothing_is_signed_or_accepted() {
        let em = ElectionManager::new("n1".to_string(), 150, 300);
        em.increment_term_and_vote_for_self();
        assert_eq!(em.vote_count_for_term(1), 0, "no identity, no self-grant");
        assert!(em.sign_grant(1, "n2").is_none());

        let decision = em.process_result(
            &ElectionResult {
                term: 1,
                elected_id: "n2".to_string(),
                grants: Vec::new(),
            },
            3,
        );
        assert_eq!(decision, ResultDecision::Rejected(ResultRejection::NoClusterIdentity));
    }
}
