pub mod client;
pub mod frame;
pub mod identity;
pub mod server;

use tracing::{debug, warn};

use crate::election::{ResultDecision, ResultRejection};
use crate::node::NodeState;
use crate::protocol::ElectionResult;

/// Reason a node that is not the Main gives for refusing a join (N-M).
///
/// Expected during a failover or when a worker's seed list contains other
/// workers, so the client logs it at debug rather than warn.
pub(crate) const JOIN_REJECT_NOT_MAIN: &str = "responder is not the cluster main";

/// Apply an inbound `ElectionResult`, shared by the server and client recv paths.
///
/// # Security (H-9 + H-11)
///
/// Two independent checks must pass before the announced winner is recorded as
/// the authoritative Main (which is what unlocks its rule/config pushes through
/// the `is_current_main` gate):
///
/// * **H-9** — the winner named in the message must be the peer that actually
///   authenticated this connection, so no node can announce a result on behalf
///   of another.
/// * **H-11** — the ballot itself must be corroborated by local evidence, above
///   all by *this node's own vote* in that term. See
///   [`crate::election::ElectionManager::process_result`].
///
/// A rejected result is logged and otherwise ignored: no term change, no role
/// change, no Main identity change.
pub(crate) async fn apply_election_result(node_state: &NodeState, auth_id: &str, result: &ElectionResult) {
    // H-9: only the winner itself may announce its own election result.
    if result.elected_id != auth_id {
        warn!(
            declared = %result.elected_id,
            authenticated = %auth_id,
            "Dropping ElectionResult: elected_id does not match peer certificate identity"
        );
        return;
    }
    debug!(
        elected = %result.elected_id,
        term = result.term,
        "ElectionResult received"
    );

    let quorum_total = node_state.quorum_total().await;
    match node_state.election.process_result(result, quorum_total) {
        ResultDecision::Accepted(new_role) => {
            // Verified: this node granted its vote to the winner in this very
            // term, so the winner may now act as Main towards us.
            node_state.set_main_node_id(result.elected_id.clone()).await;
            node_state.transition_to(new_role).await;
        }
        ResultDecision::Rejected(reason) => {
            warn!(
                elected = %result.elected_id,
                term = result.term,
                voters = result.voter_ids.len(),
                "Rejecting unverifiable ElectionResult: {reason}"
            );
            step_down_if_possibly_deposed(node_state, result, &reason).await;
        }
    }
}

/// Resolve the one split-brain that H-11's stricter acceptance rule can create.
///
/// A node can legitimately fail to corroborate a *genuine* leader: in a split
/// vote the incumbent Main may have given its vote to the losing candidate, so
/// the real winner's announcement arrives with no local evidence behind it. If
/// the incumbent simply ignored it we would have two nodes believing they are
/// Main — worse than the pre-H-11 behaviour.
///
/// The safe resolution is asymmetric: an unverifiable claim can **remove**
/// authority but never grant it. The incumbent steps down to Worker without
/// recording anybody as Main and without adopting the claimed term; the re-join
/// loop then re-learns the real Main from a seed (or the next election settles
/// it). Because this only ever demotes, a forged claim costs availability of the
/// control plane, never control of it — see the crate report for the
/// signed-ballot design that removes even that.
async fn step_down_if_possibly_deposed(node_state: &NodeState, result: &ElectionResult, reason: &ResultRejection) {
    // Only a claim that could plausibly be real: a declared member announcing a
    // term at least as new as ours. Self-inconsistent ballots and stale terms
    // carry no weight.
    let plausible = matches!(
        reason,
        ResultRejection::UnobservedTerm { .. } | ResultRejection::NoLocalVote { .. }
    ) && node_state.election.is_declared_member(&result.elected_id);
    if !plausible {
        return;
    }
    if node_state.current_role().await != waf_common::config::NodeRole::Main {
        return;
    }
    warn!(
        claimant = %result.elected_id,
        term = result.term,
        "Another member claims leadership at this term or later; standing down as Main and re-verifying"
    );
    node_state.demote_to_worker().await;
}
