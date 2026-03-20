//! Election P3 integration tests.
//!
//! Exercises the Raft-lite election state machine, phi-accrual failure detection,
//! and split-brain prevention fencing without requiring a live QUIC cluster.

use std::net::SocketAddr;
use std::sync::Arc;

use waf_cluster::{
    ClusterConfig, NodeRole, NodeState, StorageMode,
    election::ElectionManager,
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
    node.election
        .record_vote_for_me(term, "voter-1".to_string());

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

/// A node with a higher term must reject an ElectionResult from a lower-term leader.
///
/// Tests: is_valid_term fencing, advance_term, process_result correctness for both
///        stale and valid results, and that we become Main when elected.
#[tokio::test]
async fn stale_election_result_rejected() {
    let em = ElectionManager::new("node-a".to_string(), 150, 300);

    // Advance to term 5.
    for _ in 0..5 {
        em.increment_term_and_vote_for_self();
    }
    assert_eq!(em.current_term_sync(), 5);

    // A result claiming leadership at term 3 (stale — less than current term 5).
    let stale = ElectionResult {
        term: 3,
        elected_id: "stale-leader".to_string(),
        voter_ids: vec!["stale-leader".to_string(), "zombie-1".to_string()],
    };
    let role = em.process_result(&stale).await.expect("process_result");
    assert_eq!(
        role,
        NodeRole::Worker,
        "stale-term result must not grant Main role"
    );
    assert_eq!(
        em.current_term_sync(),
        5,
        "term must not be rolled back by stale result"
    );

    // A valid result at term 5 electing someone else → we step down to Worker.
    let valid_other = ElectionResult {
        term: 5,
        elected_id: "node-b".to_string(),
        voter_ids: vec![
            "node-a".to_string(),
            "node-b".to_string(),
            "node-c".to_string(),
        ],
    };
    let role = em
        .process_result(&valid_other)
        .await
        .expect("process_result");
    assert_eq!(
        role,
        NodeRole::Worker,
        "node-a should step down when node-b wins"
    );

    // A valid result at term 6 electing us → we become Main.
    let valid_us = ElectionResult {
        term: 6,
        elected_id: "node-a".to_string(),
        voter_ids: vec!["node-a".to_string(), "node-b".to_string()],
    };
    let role = em.process_result(&valid_us).await.expect("process_result");
    assert_eq!(
        role,
        NodeRole::Main,
        "node-a must become Main when it is elected"
    );
    assert_eq!(
        em.current_term_sync(),
        6,
        "term should advance to 6 after valid result"
    );
}

// ─── Test 3: Concurrent election — only the majority winner survives ──────────

/// Two candidates compete for the same term in a 5-node cluster.
///
/// Candidate A gets 2 votes (self + node-3) — not majority.
/// Candidate B gets 3 votes (self + node-4 + node-5) — majority wins.
///
/// A receives B's ElectionResult and must step down. B processes its own
/// result and must become Main. Votes are per-term and de-duplicated.
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
    let result = ElectionResult {
        term: 1,
        elected_id: "node-2".to_string(),
        voter_ids: em_b.voter_ids_for_term(1),
    };

    // A receives the result and steps down.
    let a_role = em_a
        .process_result(&result)
        .await
        .expect("A process_result");
    assert_eq!(
        a_role,
        NodeRole::Worker,
        "losing candidate A must step down"
    );

    // B processes its own result and becomes Main.
    let b_role = em_b
        .process_result(&result)
        .await
        .expect("B process_result");
    assert_eq!(
        b_role,
        NodeRole::Main,
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
    assert!(em.process_vote(&vote_a).await.expect("vote_a first"));
    // Same candidate again: still granted (idempotent).
    assert!(em.process_vote(&vote_a).await.expect("vote_a repeat"));
    // Different candidate in same term: denied.
    assert!(!em.process_vote(&vote_b).await.expect("vote_b denied"));

    // Stale term: denied regardless.
    let vote_old = ElectionVote {
        term: 0,
        candidate_id: "cand-a".to_string(),
        last_log_index: 0,
        voter_id: None,
    };
    assert!(!em.process_vote(&vote_old).await.expect("stale vote"));
}
