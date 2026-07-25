//! Election P3 integration tests.
//!
//! Exercises the Raft-lite election state machine, phi-accrual failure detection,
//! and split-brain prevention fencing without requiring a live QUIC cluster.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::net::SocketAddr;
use std::sync::Arc;

use waf_cluster::{
    ClusterConfig, NodeRole, NodeState, StorageMode,
    election::{ElectionManager, MAX_BALLOT_GRANTS, MAX_TERM_JUMP, ResultDecision, ResultRejection},
    node::PeerInfo,
    protocol::{ElectionResult, ElectionVote, SignedGrant},
};

mod common;
use common::{TestPki, signature_forgery};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn random_loopback_addr() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    sock.local_addr().expect("local_addr")
}

fn make_node(node_id: &str, pki: &TestPki) -> Arc<NodeState> {
    let cfg = ClusterConfig {
        node_id: node_id.to_string(),
        listen_addr: random_loopback_addr().to_string(),
        ..ClusterConfig::default()
    };
    let node = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"));
    node.attach_cluster_identity(pki.identity(node_id));
    node
}

/// An election manager wired to a signing identity under `pki`.
fn manager(node_id: &str, pki: &TestPki) -> ElectionManager {
    let em = ElectionManager::new(node_id.to_string(), 150, 300);
    em.attach_identity(pki.identity(node_id));
    em
}

fn vote_request(term: u64, candidate: &str) -> ElectionVote {
    ElectionVote {
        term,
        candidate_id: candidate.to_string(),
        last_log_index: 0,
        voter_id: None,
        grant: None,
    }
}

/// Ask `em` to grant its vote to `candidate` for `term`, asserting it did.
fn grant_vote(em: &ElectionManager, candidate: &str, term: u64) {
    let granted = em.process_vote(&vote_request(term, candidate)).expect("process_vote");
    assert!(granted, "{candidate} should have been granted a vote for term {term}");
}

/// An announcement whose ballot is a list of *names* with no valid signatures —
/// the pre-H-12 threat model, expressed in the new wire format.
fn unsigned_claim(term: u64, elected: &str) -> ElectionResult {
    ElectionResult {
        term,
        elected_id: elected.to_string(),
        grants: Vec::new(),
    }
}

// ─── Test 1: Candidate collects majority and wins election ────────────────────

/// A candidate with one peer that grants a vote wins the election (2/2 = majority).
///
/// Tests: increment_term_and_vote_for_self, record_grant, is_majority,
///        vote_count_for_term, grants_for_term, promote_to_main.
#[tokio::test]
async fn candidate_with_majority_wins_election() {
    let pki = TestPki::new();
    let node = make_node("candidate-1", &pki);

    // Add one peer (worker).
    {
        let mut peers = node.peers.write().await;
        peers.push(PeerInfo {
            node_id: "voter-1".to_string(),
            addr: random_loopback_addr(),
            role: NodeRole::Worker,
            last_seen_ms: 0,
        });
    }

    // Candidate increments term and auto-votes for itself — with a signature.
    let term = node.election.increment_term_and_vote_for_self();
    assert_eq!(term, 1);
    assert_eq!(node.election.vote_count_for_term(term), 1);

    // Simulate voter-1 granting the vote (normally arrives via QUIC recv).
    let grant = pki.grant("voter-1", term, "candidate-1");
    assert!(node.election.record_grant(term, &grant, "voter-1"));

    let vote_count = node.election.vote_count_for_term(term);
    let total = node.total_nodes().await; // 1 peer + self = 2

    assert!(
        ElectionManager::is_majority(vote_count, total),
        "2 votes out of 2 nodes should be majority (got {vote_count}/{total})"
    );

    let voter_ids = node.election.voter_ids_for_term(term);
    assert!(voter_ids.contains(&"candidate-1".to_string()));
    assert!(voter_ids.contains(&"voter-1".to_string()));
    assert_eq!(
        node.election.grants_for_term(term).len(),
        2,
        "the announced ballot carries one signature per voter"
    );

    // Win the election.
    node.promote_to_main().await;

    assert_eq!(
        node.current_role().await,
        NodeRole::Main,
        "candidate must be Main after winning election"
    );
}

// ─── Test 2: Stale ElectionResult is rejected (split-brain prevention) ────────

/// A node with a higher term must reject an ElectionResult from a lower-term leader,
/// and a proven result at the current term is honoured.
#[tokio::test]
async fn stale_election_result_rejected() {
    let pki = TestPki::new();
    let em = manager("node-a", &pki);
    let quorum_total = 3;

    // Advance to term 5.
    for _ in 0..5 {
        em.increment_term_and_vote_for_self();
    }
    assert_eq!(em.current_term_sync(), 5);

    // A result claiming leadership at term 3 (stale — less than current term 5),
    // even though its quorum certificate is perfectly genuine for term 3.
    let stale = pki.election_result(3, "stale-leader", &["stale-leader", "zombie-1"]);
    assert!(
        matches!(
            em.process_result(&stale, quorum_total),
            ResultDecision::Rejected(ResultRejection::StaleTerm { .. })
        ),
        "stale-term result must not grant Main role"
    );
    assert_eq!(
        em.current_term_sync(),
        5,
        "term must not be rolled back by stale result"
    );

    // A proven majority at term 6 → node-a steps down to Worker.
    let valid_other = pki.election_result(6, "node-b", &["node-a", "node-b", "node-c"]);
    assert_eq!(
        em.process_result(&valid_other, quorum_total),
        ResultDecision::Accepted(NodeRole::Worker),
        "node-a should follow the node that proved a majority"
    );
    assert_eq!(em.current_term_sync(), 6);

    // A result at term 7 electing us, after we stood for election ourselves.
    let term = em.increment_term_and_vote_for_self();
    assert_eq!(term, 7);
    let valid_us = pki.election_result(7, "node-a", &["node-a", "node-b"]);
    assert_eq!(
        em.process_result(&valid_us, quorum_total),
        ResultDecision::Accepted(NodeRole::Main),
        "node-a must become Main when it is elected"
    );
    assert_eq!(em.current_term_sync(), 7);
}

// ─── Test 3: Concurrent election — only the majority winner survives ──────────

/// Two candidates compete for the same term in a 5-node cluster.
///
/// Candidate A gets 2 votes (self + node-3) — not majority.
/// Candidate B gets 3 votes (self + node-4 + node-5) — majority wins.
///
/// Every node — including the losing candidate A, which voted for itself — can
/// recount B's quorum certificate, so all of them converge on B. Under the H-11
/// local-vote anchor A had to fall back on its own "insufficient votes" timeout;
/// with signed ballots it follows the proven winner directly.
#[tokio::test]
async fn concurrent_election_only_majority_wins() {
    let pki = TestPki::new();
    let em_a = manager("node-1", &pki);
    let em_b = manager("node-2", &pki);

    // Both start an election for term 1.
    let term_a = em_a.increment_term_and_vote_for_self();
    let term_b = em_b.increment_term_and_vote_for_self();
    assert_eq!(term_a, 1);
    assert_eq!(term_b, 1);

    // node-3 votes for A (2 total).
    let a3 = pki.grant("node-3", 1, "node-1");
    assert!(em_a.record_grant(1, &a3, "node-3"));
    // Duplicate vote from node-3 is ignored.
    assert!(!em_a.record_grant(1, &a3, "node-3"));

    // node-4 and node-5 vote for B (3 total).
    let b4 = pki.grant("node-4", 1, "node-2");
    let b5 = pki.grant("node-5", 1, "node-2");
    assert!(em_b.record_grant(1, &b4, "node-4"));
    assert!(em_b.record_grant(1, &b5, "node-5"));

    let total = 5usize; // 5-node cluster

    let a_votes = em_a.vote_count_for_term(1);
    let b_votes = em_b.vote_count_for_term(1);

    assert_eq!(a_votes, 2, "A: self + node-3 = 2 votes");
    assert_eq!(b_votes, 3, "B: self + node-4 + node-5 = 3 votes");

    // Only B has majority (3 >= (5/2)+1 = 3).
    assert!(
        !ElectionManager::is_majority(a_votes, total),
        "A with {a_votes}/{total} votes must NOT be majority"
    );
    assert!(
        ElectionManager::is_majority(b_votes, total),
        "B with {b_votes}/{total} votes must be majority"
    );

    // B broadcasts its ElectionResult, carrying the three signatures it holds.
    let announced = ElectionResult {
        term: 1,
        elected_id: "node-2".to_string(),
        grants: em_b.grants_for_term(1),
    };

    // node-4 granted its vote to B and follows it.
    let em_d = manager("node-4", &pki);
    grant_vote(&em_d, "node-2", 1);
    assert_eq!(
        em_d.process_result(&announced, total),
        ResultDecision::Accepted(NodeRole::Worker),
        "a node that voted for the winner follows it"
    );

    // A voted for itself, but B's certificate speaks for itself.
    assert_eq!(
        em_a.process_result(&announced, total),
        ResultDecision::Accepted(NodeRole::Worker),
        "a losing candidate follows a winner that can prove its majority"
    );

    // B processes its own result and becomes Main.
    assert_eq!(
        em_b.process_result(&announced, total),
        ResultDecision::Accepted(NodeRole::Main),
        "winning candidate B must become Main"
    );

    // Both converge on term 1.
    assert_eq!(em_a.current_term_sync(), 1);
    assert_eq!(em_b.current_term_sync(), 1);
}

// ─── Test 4: Vote grant is idempotent for same candidate ─────────────────────

/// A node may grant its vote to the same candidate multiple times without error,
/// but must deny a second, different candidate in the same term. That
/// one-vote-per-term rule is what makes two conflicting quorum certificates for
/// one term impossible.
#[tokio::test]
async fn vote_grant_idempotent_deny_different_candidate() {
    let pki = TestPki::new();
    let em = manager("voter", &pki);

    let vote_a = vote_request(1, "cand-a");
    let vote_b = vote_request(1, "cand-b");

    // First vote for cand-a: granted.
    assert!(em.process_vote(&vote_a).expect("vote_a first"));
    // Same candidate again: still granted (idempotent).
    assert!(em.process_vote(&vote_a).expect("vote_a repeat"));
    // Different candidate in same term: denied.
    assert!(!em.process_vote(&vote_b).expect("vote_b denied"));

    // Stale term: denied regardless.
    assert!(!em.process_vote(&vote_request(0, "cand-a")).expect("stale vote"));
}

// ─── H-12: forged ElectionResult attack scenarios ─────────────────────────────

/// **Attack ①** — a compromised but validly-authenticated worker announces
/// itself as Main with an empty ballot and a maximal term.
#[tokio::test]
async fn forged_election_result_with_empty_ballot_and_max_term_is_rejected() {
    let pki = TestPki::new();
    let node = make_node("victim", &pki);
    node.election
        .set_members(&["victim".to_string(), "peer-1".to_string(), "usurper".to_string()]);
    // Cluster is quietly running at term 4 with "peer-1" as the elected Main.
    grant_vote(&node.election, "peer-1", 4);
    node.set_main_node_id("peer-1".to_string()).await;

    let forged = unsigned_claim(u64::MAX, "usurper");
    assert!(
        matches!(
            node.election.process_result(&forged, node.quorum_total().await),
            ResultDecision::Rejected(ResultRejection::ImplausibleTerm { .. })
        ),
        "a zero-vote takeover claim must be rejected"
    );
    assert_eq!(
        node.election.current_term_sync(),
        4,
        "an unverifiable result must not advance the term (u64::MAX lockout)"
    );
    assert_eq!(
        node.main_node_id().await.as_deref(),
        Some("peer-1"),
        "the usurper must not become the authoritative Main"
    );
    assert_eq!(node.current_role().await, NodeRole::Worker);

    // The same empty ballot at a plausible term fails on the recount instead.
    assert!(matches!(
        node.election.process_result(&unsigned_claim(4, "usurper"), 3),
        ResultDecision::Rejected(ResultRejection::WinnerNotInBallot { .. })
    ));
}

/// **Attack ①b (the H-12 headline)** — minority usurpation. The usurper really
/// did collect this node's vote, so the H-11 local anchor holds; it then pads
/// the ballot to a quorum with fabrications. Only a signature recount refuses
/// this.
#[tokio::test]
async fn minority_winner_cannot_pad_the_ballot_to_a_quorum() {
    let pki = TestPki::new();
    let foreign = TestPki::new();
    let em = manager("victim", &pki);
    em.set_members(&["victim", "peer-1", "peer-2", "peer-3", "usurper"].map(String::from));

    // Our vote genuinely goes to the usurper.
    grant_vote(&em, "usurper", 1);

    let forged = ElectionResult {
        term: 1,
        elected_id: "usurper".to_string(),
        grants: vec![
            // Genuine: the usurper's self-vote and our own grant.
            pki.grant("usurper", 1, "usurper"),
            pki.grant("victim", 1, "usurper"),
            // Fabricated: right certificate, wrong key.
            signature_forgery(&pki, "peer-1", 1, "usurper"),
            // Fabricated: certificate from a CA we do not trust.
            foreign.grant("peer-2", 1, "usurper"),
            // Fabricated: a grant peer-3 really signed, but for another term.
            pki.grant("peer-3", 2, "usurper"),
        ],
    };

    assert!(
        matches!(
            em.process_result(&forged, 5),
            ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 2, .. })
        ),
        "a fabricated ballot must not turn a minority into a quorum, even for a node that did vote for the claimant"
    );
    assert!(
        !em.process_result(&forged, 5).is_accepted(),
        "repeating the attack does not wear the check down"
    );
}

/// A grant signed for another *candidate* in the same term cannot be
/// re-addressed: the payload binds both fields.
#[tokio::test]
async fn grants_cannot_be_moved_between_candidates() {
    let pki = TestPki::new();
    let em = manager("victim", &pki);
    em.set_members(&["victim", "honest", "n3", "n4", "usurper"].map(String::from));

    // Three members really voted — for "honest", not for the usurper.
    let stolen = pki.grants(&["victim", "n3", "n4"], 1, "honest");
    let mut ballot = pki.grants(&["usurper"], 1, "usurper");
    ballot.extend(stolen);

    let forged = ElectionResult {
        term: 1,
        elected_id: "usurper".to_string(),
        grants: ballot,
    };
    assert!(
        matches!(
            em.process_result(&forged, 5),
            ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 1, .. })
        ),
        "grants addressed to another candidate must not count"
    );
}

/// One voter cannot be counted twice, however many certificates it presents.
#[tokio::test]
async fn duplicate_voters_are_counted_once() {
    let pki = TestPki::new();
    let em = manager("victim", &pki);
    em.set_members(&["victim", "n2", "n3", "n4", "usurper"].map(String::from));

    // Five grants for a five-member cluster — within the ballot limit, but only
    // two distinct voters sit behind them.
    let mut grants = pki.grants(&["usurper"], 1, "usurper");
    for _ in 0..4 {
        grants.push(pki.grant("n2", 1, "usurper"));
    }
    let stuffed = ElectionResult {
        term: 1,
        elected_id: "usurper".to_string(),
        grants,
    };
    assert!(matches!(
        em.process_result(&stuffed, 5),
        ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 2, .. })
    ));
}

/// An oversized ballot is refused before a single signature is checked, so a
/// hostile peer cannot turn one message into unbounded verification work.
#[tokio::test]
async fn oversized_ballots_are_refused_before_verification() {
    let pki = TestPki::new();
    let em = manager("victim", &pki);
    let filler = SignedGrant {
        cert_b64: String::new(),
        chain_b64: Vec::new(),
        signature_b64: String::new(),
    };
    let flood = ElectionResult {
        term: 1,
        elected_id: "usurper".to_string(),
        grants: vec![filler; MAX_BALLOT_GRANTS + 1],
    };
    assert!(
        matches!(
            em.process_result(&flood, 5),
            ResultDecision::Rejected(ResultRejection::BallotTooLarge { .. })
        ),
        "without a declared membership the global cap applies"
    );

    // With a declared membership the bound is exact: a legitimate ballot can
    // never hold more grants than the cluster has members.
    em.set_members(&["victim", "n2", "n3"].map(String::from));
    let over = ElectionResult {
        term: 1,
        elected_id: "n2".to_string(),
        grants: pki.grants(&["n2", "n3", "victim", "ghost"], 1, "n2"),
    };
    assert!(matches!(
        em.process_result(&over, 3),
        ResultDecision::Rejected(ResultRejection::BallotTooLarge { limit: 3, .. })
    ));
}

/// **Attack ①c** — an honest-looking result that simply does not add up to a
/// quorum is refused even when this node did vote for the candidate.
#[tokio::test]
async fn election_result_short_of_quorum_is_rejected() {
    let pki = TestPki::new();
    let em = manager("voter", &pki);
    em.set_members(&["voter", "cand", "n3", "n4", "n5"].map(String::from));
    grant_vote(&em, "cand", 1);

    // Only 2 of 5 members: the candidate and us.
    let thin = pki.election_result(1, "cand", &["cand", "voter"]);
    assert!(
        matches!(
            em.process_result(&thin, 5),
            ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 2, .. })
        ),
        "a minority ballot must not install a Main"
    );

    // A ballot without the winner's own vote is nonsense.
    let no_winner = pki.election_result(1, "cand", &["voter", "n3", "n4"]);
    assert!(matches!(
        em.process_result(&no_winner, 5),
        ResultDecision::Rejected(ResultRejection::WinnerNotInBallot { .. })
    ));

    // Same election, now with a real majority (3 of 5) → accepted.
    let genuine = pki.election_result(1, "cand", &["cand", "voter", "n3"]);
    assert_eq!(
        em.process_result(&genuine, 5),
        ResultDecision::Accepted(NodeRole::Worker),
        "the genuine winner of the election we voted in is still honoured"
    );
}

/// **Attack ①d** — a node outside the declared membership can never be Main,
/// its grants never count, and term 0 is never the product of an election.
#[tokio::test]
async fn ineligible_winner_and_zero_term_are_rejected() {
    let pki = TestPki::new();
    let em = manager("voter", &pki);
    em.set_members(&["voter", "n2", "n3"].map(String::from));

    assert!(matches!(
        em.process_result(&pki.election_result(0, "n2", &["n2", "voter"]), 3),
        ResultDecision::Rejected(ResultRejection::ZeroTerm)
    ));

    // "outsider" is not declared, so it is not even granted a vote.
    assert!(
        !em.process_vote(&vote_request(1, "outsider")).expect("process_vote"),
        "a non-member must not be granted a vote"
    );
    em.advance_term(1);
    assert!(matches!(
        em.process_result(&pki.election_result(1, "outsider", &["outsider", "voter", "n2"]), 3),
        ResultDecision::Rejected(ResultRejection::IneligibleWinner { .. })
    ));

    // A properly signed grant from a node outside the membership is discarded,
    // so it cannot make up the numbers for an eligible winner either.
    let padded = ElectionResult {
        term: 1,
        elected_id: "n2".to_string(),
        grants: {
            let mut g = pki.grants(&["n2"], 1, "n2");
            g.extend(pki.grants(&["outsider-a", "outsider-b"], 1, "n2"));
            g
        },
    };
    assert!(matches!(
        em.process_result(&padded, 3),
        ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 1, .. })
    ));
}

/// **Attack ①e** — term inflation. A single forged message may move the term by
/// at most `MAX_TERM_JUMP`, so it cannot saturate `u64` and freeze every future
/// election (`voted_for` is only released when the term advances).
#[tokio::test]
async fn term_jumps_are_clamped_and_never_overflow() {
    let pki = TestPki::new();
    let em = manager("victim", &pki);

    let reached = em.advance_term(u64::MAX);
    assert_eq!(reached, MAX_TERM_JUMP, "a single message may only jump MAX_TERM_JUMP");

    // A vote request implausibly far ahead is denied but still pulls us up.
    let denied = em
        .process_vote(&vote_request(u64::MAX, "flooder"))
        .expect("process_vote");
    assert!(!denied, "an implausible term jump must not win our vote");
    assert_eq!(em.current_term_sync(), MAX_TERM_JUMP * 2);

    // A node that is genuinely a few terms ahead still converges immediately.
    let ahead = MAX_TERM_JUMP * 2 + 3;
    assert!(
        em.process_vote(&vote_request(ahead, "peer")).expect("process_vote"),
        "a plausible term advance is still granted a vote"
    );
    assert_eq!(em.current_term_sync(), ahead);

    // Terms saturate instead of wrapping back to 0.
    let em2 = manager("edge", &pki);
    for _ in 0..u64::MAX.div_euclid(MAX_TERM_JUMP).min(4) {
        em2.advance_term(u64::MAX);
    }
    assert!(em2.increment_term_and_vote_for_self() > 0);
}

/// A grant fabricated for a term this node never ran in is discarded instead of
/// being parked in the ballot map.
#[tokio::test]
async fn vote_grants_for_unrun_terms_are_discarded() {
    let pki = TestPki::new();
    let em = manager("cand", &pki);
    let term = em.increment_term_and_vote_for_self();
    let ghost_max = pki.grant("ghost", u64::MAX, "cand");
    let ghost_next = pki.grant("ghost", term + 1, "cand");
    assert!(!em.record_grant(u64::MAX, &ghost_max, "ghost"));
    assert!(!em.record_grant(term + 1, &ghost_next, "ghost"));
    assert_eq!(em.vote_count_for_term(term), 1, "only the self-vote counts");
    assert_eq!(em.vote_count_for_term(u64::MAX), 0);
}
