#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Shared embedded and standalone Minecraft room runtime.
pub mod activity;
mod activity_evidence;
mod bearer;
mod central;
pub mod forwarding;
mod login;
mod mcp;
pub mod native;
pub mod ops;
mod ops_extended;
pub mod protocol;
pub mod rooms;
pub mod scoring;
pub mod skins;

#[allow(dead_code)]
mod skin_contracts {
    include!(concat!(env!("OUT_DIR"), "/skin_contracts.rs"));
}

#[allow(dead_code, clippy::unwrap_used, clippy::possible_missing_else)]
mod game_contracts {
    include!(concat!(env!("OUT_DIR"), "/game_contracts.rs"));
}

pub use node::{Error, Result};

fn operation_error(error: anyhow::Error) -> Error {
    match error.downcast::<Error>() {
        Ok(error) => error,
        Err(error) => Error::Protocol(error.to_string()),
    }
}

mod ai_worker;
pub mod bootstrap;
pub mod identity_bridge;
mod notifications;
mod report_board;
pub mod runtime;
mod workflow_worker;

#[cfg(test)]
#[path = "../../union-core/tests/support/mod.rs"]
mod test_identity;
