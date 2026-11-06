//! Identity and application bootstrap for game clients.
use crate::{Node, Result};
pub use client::trust::*;

/// Fetch the identity and optional application chains for TOFU bootstrap.
/// Identity errors fail the bootstrap; any application fetch or verification error
/// yields `application: null`. Successful pins are recomputed and bound locally by
/// the single-chain helpers. The caller owns the node, timeout and durable pins.
pub async fn fetch_genesis_chains(
    node: &Node,
    address: &str,
    peer: &str,
) -> Result<serde_json::Value> {
    let (genesis, pin) = fetch_identity_genesis(node, address, peer).await?;
    let application = fetch_business_genesis::<crate::application::Application>(
        node,
        address,
        peer,
        &pin,
        crate::journal::PROTOCOL,
    )
    .await
    .map(|(_, pin)| serde_json::json!({"genesis_hash": pin}))
    .unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({
        "identity": {"genesis": genesis, "genesis_hash": pin},
        "application": application,
    }))
}
