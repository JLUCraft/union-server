#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! League domain; the platform state machine does not depend on this crate.
pub use identity::PeerId;
pub use protocol::{self, Error, Result};
pub mod governance;
pub mod season;
pub use governance::{LeagueAction, LeagueDomain, LeagueState};

pub mod application;
pub mod discovery;
pub mod events;
pub mod files;
pub mod points;
pub mod trust;

pub use client::{
    AddressProtocol, Identity, Multiaddr, Node, NodeConfig, endpoint, generic, journal,
};
use office_events::MAX_RECORDS;
pub use office_events::office;
