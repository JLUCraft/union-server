//! Execution of centrally authorized operations in a separate supervisor process.
mod config;
mod fleet;
mod http;
mod jobs;

pub use config::Config;
pub use http::Supervisor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid operations request: {0}")]
    Invalid(String),
    #[error("operation conflicts with the saved request")]
    Conflict,
    #[error("operation authorization expired")]
    Expired,
    #[error("executor authorization required")]
    Unauthorized,
    #[error("operation not found")]
    NotFound,
    #[error("supervisor is stopping")]
    Stopping,
    #[error("operations storage is unavailable")]
    StorageUnavailable,
    #[error("system clock precedes the Unix epoch")]
    Clock,
    #[error("operations I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("operations JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("operations database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("instance operation: {0}")]
    Instance(#[from] minecraftd::service::instance::InstanceServiceError),
}
pub type Result<T> = std::result::Result<T, Error>;

fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Clock)
}
