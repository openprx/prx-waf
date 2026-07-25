pub mod client;
pub mod frame;
pub mod identity;
pub mod server;

use tracing::{debug, warn};

use crate::election::ResultDecision;
use crate::node::NodeState;
use crate::protocol::ElectionResult;

/// Reason a node that is not the Main gives for refusing a join (N-M).
///
/// Expected during a failover or when a worker's seed list contains other
/// workers, so the client logs it at debug rather than warn.
pub(crate) const JOIN_REJECT_NOT_MAIN: &str = "responder is not the cluster main";

/// Apply an inbound `ElectionResult`, shared by the server and client recv paths.
///
/// # Security (H-9 + H-12)
///
/// Two independent checks must pass before the announced winner is recorded as
/// the authoritative Main (which is what unlocks its rule/config pushes through
/// the `is_current_main` gate):
///
/// * **H-9** — the winner named in the message must be the peer that actually
///   authenticated this connection, so no node can announce a result on behalf
///   of another.
/// * **H-12** — the ballot must be a quorum certificate: a majority of distinct
///   declared members, each proved by a CA-chained signature over this exact
///   term and winner. See
///   [`crate::election::ElectionManager::process_result`].
///
/// A rejected result is logged and otherwise ignored: no term change, no role
/// change, no Main identity change. Unlike the H-11 design this path no longer
/// needs a compensating step-down for claims it cannot corroborate — a genuine
/// leader is now verifiable by every node, so an unverifiable claim is simply
/// false and is dropped. That closes the availability hole where a rogue member
/// could depose the real Main by spamming claims it could never prove.
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

    // The denominator is never smaller than two. `quorum_total` falls back to
    // the *live* peer view when no membership is declared, and that view can be
    // momentarily empty (fresh start, post-eviction, partition), which would
    // make a single self-signed grant a "majority of one". Receiving this
    // message is itself proof that the cluster holds at least two nodes — us and
    // the winner — so a lone signature can never carry an election.
    let quorum_total = node_state.quorum_total().await.max(2);
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
                grants = result.grants.len(),
                "Rejecting unverifiable ElectionResult: {reason}"
            );
        }
    }
}
