#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Central Minecraft gateway, scoring, and activity host.
pub mod activity;
mod bearer;
mod central;
pub mod forwarding;
mod login;
pub mod native;
pub mod protocol;
pub mod scoring;
pub mod skins;

pub mod skin_contracts {
    include!(concat!(env!("OUT_DIR"), "/skin_contracts.rs"));
}

pub mod game_contracts {
    include!(concat!(env!("OUT_DIR"), "/game_contracts.rs"));
}

pub mod point_contracts {
    include!(concat!(env!("OUT_DIR"), "/point_contracts.rs"));
}

mod service;
pub use service::Service;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("host configuration: {0}")]
    Configuration(#[source] anyhow::Error),
    #[error("{service}: {source}")]
    Service {
        service: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("{0} service stopped")]
    ServiceStopped(&'static str),
}
pub type Result<T> = std::result::Result<T, Error>;

pub mod runtime;
