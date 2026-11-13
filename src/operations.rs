//! Execution of centrally authorized operations in a separate supervisor process.
mod authority;
mod backups;
mod capture;
mod config;
mod deployment;
mod fleet;
mod http;
mod jobs;
mod observe;

pub use config::Config;
pub use http::Supervisor;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{operation}; recovery failed: {recovery}")]
    Recovery {
        #[source]
        operation: Box<Error>,
        recovery: Box<Error>,
    },
    #[error("invalid operations request: {0}")]
    Invalid(String),
    #[error("operation conflicts with the saved request")]
    Conflict,
    #[error("operation authorization expired")]
    Expired,
    #[error("executor authorization required")]
    Unauthorized,
    #[error("central execution authorization denied")]
    Authorization,
    #[error("authority request: {0}")]
    Request(#[from] reqwest::Error),
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
    #[error("archive operation: {0}")]
    Archive(#[from] minecraftd::archive::ArchiveError),
    #[error("backup encryption: {0}")]
    Encryption(String),
    #[error("operations JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("operations database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("operations task: {0}")]
    Task(#[from] tokio::task::JoinError),
    #[error("instance operation: {0}")]
    Instance(#[from] minecraftd::service::instance::InstanceServiceError),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    fn with_recovery(self, result: Result<()>) -> Self {
        match result {
            Ok(()) => self,
            Err(recovery) => Self::Recovery {
                operation: Box::new(self),
                recovery: Box::new(recovery),
            },
        }
    }
}

fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Clock)
}
