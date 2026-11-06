//! Game composition with office records, workflows, and points.
mod domain;
pub mod points;
pub mod workflows;

pub use crate::office::activities::{Event, Phase, Task, Window};
pub use domain::{EventAction, EventsDomain, EventsState};

pub use office_events::{files, office};
