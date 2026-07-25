//! Election P3 integration tests.
//!
//! Exercises the Raft-lite election state machine, phi-accrual failure detection,
//! and split-brain prevention fencing without requiring a live QUIC cluster.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::net::SocketAddr;
use std::sync::Arc;

use waf_cluster::{
    ClusterConfig, NodeRole, NodeState, StorageMode,
    election::{ElectionManager, MAX_TERM_JUMP, ResultDecision, ResultRejection},
    node::PeerInfo,
    protocol::{ElectionResult, ElectionVote},
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn random_loopback_addr() -> SocketAddr {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    sock.local_addr().expect("local_addr")
}

fn make_node(node_id: &str) -> Arc<NodeState> {
    let cfg = ClusterConfig {
        node_id: node_id.to_string(),
        listen_addr: random_loopback_addr().to_string(),
        ..ClusterConfig::default()
    };
    Arc::new(NodeState::new(cfg, StorageMode::Full).expect("NodeState::new"))
}

/// Ask `em` to grant its vote to `candidate` for `term`, asserting it did.
fn grant_vote(em: &ElectionManager, candidate: &str, term: u64) {
    let granted = em
        .process_vote(&ElectionVote {
            term,
            candidate_id: candidate.to_string(),
            last_log_index: 0,
            voter_id: None,
        })
        .expect("process_vote");
    assert!(granted, "{candidate} should have been granted a vote for term {term}");
}

fn result(term: u64, elected: &str, voters: &[&str]) -> ElectionResult {
    ElectionResult {
        term,
        elected_id: elected.to_string(),
        voter_ids: voters.iter().map(|s| (*s).to_string()).collect(),
    }
}

// ─── Test 1: Candidate collects majority and wins election ────────────────────

/// A candidate with one peer that grants a vote wins the election (2/2 = majority).
///
/// Tests: increment_term_and_vote_for_self, record_vote_for_me, is_majority,
///        vote_count_for_term, voter_ids_for_term, promote_to_main.
#[tokio::test]
async fn candidate_with_majority_wins_election() {
    let node = make_node("candidate-1");

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

    // Candidate increments term and auto-votes for itself.
    let term = node.election.increment_term_and_vote_for_self();
    assert_eq!(term, 1);
    assert_eq!(node.election.vote_count_for_term(term), 1);

    // Simulate voter-1 granting the vote (normally arrives via QUIC recv).
    node.election.record_vote_for_me(term, "voter-1".to_string());

    let vote_count = node.election.vote_count_for_term(term);
    let total = node.total_nodes().await; // 1 peer + self = 2

    assert!(
        ElectionManager::is_majority(vote_count, total),
        "2 votes out of 2 nodes should be majority (got {vote_count}/{total})"
    );

    let voter_ids = node.election.voter_ids_for_term(term);
    assert!(voter_ids.contains(&"candidate-1".to_string()));
    assert!(voter_ids.contains(&"voter-1".to_string()));

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
/// and a corroborated result at the current term is honoured.
///
/// Tests: term fencing, the H-11 local-vote anchor, and that we become Main when
/// we are the node that was elected.
#[tokio::test]
async fn stale_election_result_rejected() {
    let em = ElectionManager::new("node-a".to_string(), 150, 300);
    let quorum_total = 3;

    // Advance to term 5.
    for _ in 0..5 {
        em.increment_term_and_vote_for_self();
    }
    assert_eq!(em.current_term_sync(), 5);

    // A result claiming leadership at term 3 (stale — less than current term 5).
    let stale = result(3, "stale-leader", &["stale-leader", "zombie-1"]);
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

    // At term 6 node-a grants its vote to node-b, so node-b's result is
    // corroborated → node-a steps down to Worker.
    grant_vote(&em, "node-b", 6);
    let valid_other = result(6, "node-b", &["node-a", "node-b", "node-c"]);
    assert_eq!(
        em.process_result(&valid_other, quorum_total),
        ResultDecision::Accepted(NodeRole::Worker),
        "node-a should step down when the node it voted for wins"
    );
    assert_eq!(em.current_term_sync(), 6);

    // A result at term 7 electing us, after we stood for election ourselves.
    let term = em.increment_term_and_vote_for_self();
    assert_eq!(term, 7);
    let valid_us = result(7, "node-a", &["node-a", "node-b"]);
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
/// node-4, which voted for B, accepts B's ElectionResult. Losing candidate A
/// never voted for B, so under H-11 it does **not** take B's word for it — it
/// steps down through its own "insufficient votes" path in the election loop
/// instead. B processes its own result and becomes Main. Votes are per-term and
/// de-duplicated.
#[tokio::test]
async fn concurrent_election_only_majority_wins() {
    let em_a = ElectionManager::new("node-1".to_string(), 150, 300);
    let em_b = ElectionManager::new("node-2".to_string(), 150, 300);

    // Both start an election for term 1.
    let term_a = em_a.increment_term_and_vote_for_self();
    let term_b = em_b.increment_term_and_vote_for_self();
    assert_eq!(term_a, 1);
    assert_eq!(term_b, 1);

    // node-3 votes for A (2 total).
    assert!(em_a.record_vote_for_me(1, "node-3".to_string()));
    // Duplicate vote from node-3 is ignored.
    assert!(!em_a.record_vote_for_me(1, "node-3".to_string()));

    // node-4 and node-5 vote for B (3 total).
    assert!(em_b.record_vote_for_me(1, "node-4".to_string()));
    assert!(em_b.record_vote_for_me(1, "node-5".to_string()));

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

    // B broadcasts ElectionResult.
    let announced = ElectionResult {
        term: 1,
        elected_id: "node-2".to_string(),
        voter_ids: em_b.voter_ids_for_term(1),
    };

    // node-4 granted its vote to B, so B's claim is corroborated locally.
    let em_d = ElectionManager::new("node-4".to_string(), 150, 300);
    grant_vote(&em_d, "node-2", 1);
    assert_eq!(
        em_d.process_result(&announced, total),
        ResultDecision::Accepted(NodeRole::Worker),
        "a node that voted for the winner follows it"
    );

    // A voted for itself, so B's announcement carries no evidence A can check.
    assert!(
        matches!(
            em_a.process_result(&announced, total),
            ResultDecision::Rejected(ResultRejection::NoLocalVote { .. })
        ),
        "a losing candidate must not adopt an unprovable leader; it steps down via its own election loop"
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
/// but must deny a second, different candidate in the same term.
#[tokio::test]
async fn vote_grant_idempotent_deny_different_candidate() {
    let em = ElectionManager::new("voter".to_string(), 150, 300);

    let vote_a = ElectionVote {
        term: 1,
        candidate_id: "cand-a".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    let vote_b = ElectionVote {
        term: 1,
        candidate_id: "cand-b".to_string(),
        last_log_index: 0,
        voter_id: None,
    };

    // First vote for cand-a: granted.
    assert!(em.process_vote(&vote_a).expect("vote_a first"));
    // Same candidate again: still granted (idempotent).
    assert!(em.process_vote(&vote_a).expect("vote_a repeat"));
    // Different candidate in same term: denied.
    assert!(!em.process_vote(&vote_b).expect("vote_b denied"));

    // Stale term: denied regardless.
    let vote_old = ElectionVote {
        term: 0,
        candidate_id: "cand-a".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    assert!(!em.process_vote(&vote_old).expect("stale vote"));
}

// ─── H-11: forged ElectionResult attack scenarios ─────────────────────────────

/// **Attack ①** — a compromised but validly-authenticated worker announces
/// itself as Main with an empty ballot and a maximal term.
///
/// Before H-11 the receiver adopted `elected_id` as the authoritative Main after
/// only checking the sender's certificate, and `is_valid_term`'s `>=` let
/// `u64::MAX` pin the term forever. Now: rejected, and nothing moves.
#[tokio::test]
async fn forged_election_result_with_empty_ballot_and_max_term_is_rejected() {
    let node = make_node("victim");
    node.election
        .set_members(&["victim".to_string(), "peer-1".to_string(), "usurper".to_string()]);
    // Cluster is quietly running at term 4 with "peer-1" as the elected Main.
    grant_vote(&node.election, "peer-1", 4);
    node.set_main_node_id("peer-1".to_string()).await;

    let forged = result(u64::MAX, "usurper", &[]);
    assert!(
        matches!(
            node.election.process_result(&forged, node.quorum_total().await),
            ResultDecision::Rejected(ResultRejection::UnobservedTerm { .. })
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
}

/// **Attack ①b** — same term as the victim, but the victim voted for somebody
/// else. A stuffed `voter_ids` list does not help: the anchor is the victim's
/// own vote, which it cannot be lied to about.
#[tokio::test]
async fn forged_election_result_with_stuffed_ballot_is_rejected() {
    let em = ElectionManager::new("victim".to_string(), 150, 300);
    em.set_members(&["victim", "peer-1", "peer-2", "peer-3", "usurper"].map(String::from));
    grant_vote(&em, "peer-1", 1);

    // Ballot claims every real member voted for the usurper.
    let forged = result(1, "usurper", &["usurper", "victim", "peer-1", "peer-2", "peer-3"]);
    assert!(
        matches!(
            em.process_result(&forged, 5),
            ResultDecision::Rejected(ResultRejection::NoLocalVote { .. })
        ),
        "a fabricated voter list must not override this node's own vote record"
    );
}

/// **Attack ①c** — an honest-looking result that simply does not add up to a
/// quorum is refused even when this node did vote for the candidate.
#[tokio::test]
async fn election_result_short_of_quorum_is_rejected() {
    let em = ElectionManager::new("voter".to_string(), 150, 300);
    em.set_members(&["voter", "cand", "n3", "n4", "n5"].map(String::from));
    grant_vote(&em, "cand", 1);

    // Only 2 of 5 members: the candidate and us.
    let thin = result(1, "cand", &["cand", "voter"]);
    assert!(
        matches!(
            em.process_result(&thin, 5),
            ResultDecision::Rejected(ResultRejection::QuorumShortfall { counted: 2, .. })
        ),
        "a minority ballot must not install a Main"
    );

    // A ballot without the winner's own vote is nonsense.
    grant_vote(&em, "cand", 1);
    let no_winner = result(1, "cand", &["voter", "n3", "n4"]);
    assert!(matches!(
        em.process_result(&no_winner, 5),
        ResultDecision::Rejected(ResultRejection::WinnerNotInBallot { .. })
    ));

    // Same election, now with a real majority (3 of 5) → accepted.
    let genuine = result(1, "cand", &["cand", "voter", "n3"]);
    assert_eq!(
        em.process_result(&genuine, 5),
        ResultDecision::Accepted(NodeRole::Worker),
        "the genuine winner of the election we voted in is still honoured"
    );
}

/// **Attack ①d** — a node outside the declared membership can never be Main,
/// and term 0 is never the product of an election.
#[tokio::test]
async fn ineligible_winner_and_zero_term_are_rejected() {
    let em = ElectionManager::new("voter".to_string(), 150, 300);
    em.set_members(&["voter", "n2", "n3"].map(String::from));

    assert!(matches!(
        em.process_result(&result(0, "n2", &["n2", "voter"]), 3),
        ResultDecision::Rejected(ResultRejection::ZeroTerm)
    ));

    // "outsider" is not declared, so it is not even granted a vote.
    assert!(
        !em.process_vote(&ElectionVote {
            term: 1,
            candidate_id: "outsider".to_string(),
            last_log_index: 0,
            voter_id: None,
        })
        .expect("process_vote"),
        "a non-member must not be granted a vote"
    );
    em.advance_term(1);
    assert!(matches!(
        em.process_result(&result(1, "outsider", &["outsider", "voter", "n2"]), 3),
        ResultDecision::Rejected(ResultRejection::IneligibleWinner { .. })
    ));
}

/// **Attack ①e** — term inflation. A single forged message may move the term by
/// at most `MAX_TERM_JUMP`, so it cannot saturate `u64` and freeze every future
/// election (`voted_for` is only released when the term advances).
#[tokio::test]
async fn term_jumps_are_clamped_and_never_overflow() {
    let em = ElectionManager::new("victim".to_string(), 150, 300);

    let reached = em.advance_term(u64::MAX);
    assert_eq!(reached, MAX_TERM_JUMP, "a single message may only jump MAX_TERM_JUMP");

    // A vote request implausibly far ahead is denied but still pulls us up.
    let denied = em
        .process_vote(&ElectionVote {
            term: u64::MAX,
            candidate_id: "flooder".to_string(),
            last_log_index: 0,
            voter_id: None,
        })
        .expect("process_vote");
    assert!(!denied, "an implausible term jump must not win our vote");
    assert_eq!(em.current_term_sync(), MAX_TERM_JUMP * 2);

    // A node that is genuinely a few terms ahead still converges immediately.
    let ahead = MAX_TERM_JUMP * 2 + 3;
    assert!(
        em.process_vote(&ElectionVote {
            term: ahead,
            candidate_id: "peer".to_string(),
            last_log_index: 0,
            voter_id: None,
        })
        .expect("process_vote"),
        "a plausible term advance is still granted a vote"
    );
    assert_eq!(em.current_term_sync(), ahead);

    // Terms saturate instead of wrapping back to 0.
    let em2 = ElectionManager::new("edge".to_string(), 150, 300);
    for _ in 0..u64::MAX.div_euclid(MAX_TERM_JUMP).min(4) {
        em2.advance_term(u64::MAX);
    }
    assert!(em2.increment_term_and_vote_for_self() > 0);
}

/// A grant fabricated for a term this node never ran in is discarded instead of
/// being parked in the ballot map.
#[tokio::test]
async fn vote_grants_for_unrun_terms_are_discarded() {
    let em = ElectionManager::new("cand".to_string(), 150, 300);
    let term = em.increment_term_and_vote_for_self();
    assert!(!em.record_vote_for_me(u64::MAX, "ghost".to_string()));
    assert!(!em.record_vote_for_me(term + 1, "ghost".to_string()));
    assert_eq!(em.vote_count_for_term(term), 1, "only the self-vote counts");
    assert_eq!(em.vote_count_for_term(u64::MAX), 0);
}
