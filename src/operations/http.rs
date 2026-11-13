use super::{Config, Error, Result, fleet::Fleet, jobs::Jobs, now};
use crate::{
    bearer::require_bearer,
    operation_contracts::{
        EXECUTOR_JOBS_PATH, EXECUTOR_SNAPSHOT_PATH, OPERATIONS_MAX_REQUEST_BYTES,
        OperationsDispatch, OperationsJob, OperationsJobState, OperationsSnapshot,
    },
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::{
    fs::File,
    future::Future,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
};
use tokio::net::TcpListener;

struct Executor {
    credential: Vec<u8>,
    fleet: Arc<Fleet>,
    jobs: Jobs,
}

pub struct Supervisor {
    listener: TcpListener,
    router: Router,
    fleet: Arc<Fleet>,
    lease: File,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::Invalid(message) => (StatusCode::BAD_REQUEST, message.as_str()),
            Error::Conflict => (StatusCode::CONFLICT, "Operation conflicts with saved state"),
            Error::Expired => (StatusCode::UNAUTHORIZED, "Operation authorization expired"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "Executor authorization required"),
            Error::NotFound => (StatusCode::NOT_FOUND, "Operation not found"),
            Error::Stopping => (StatusCode::SERVICE_UNAVAILABLE, "Supervisor is stopping"),
            _ => {
                tracing::error!(error = %self, "operations executor failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed")
            }
        };
        (status, Json(serde_json::json!({"errorMessage": message}))).into_response()
    }
}

async fn snapshot(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
) -> Result<Json<OperationsSnapshot>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    Ok(Json(executor.fleet.snapshot().await?))
}

async fn job(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<OperationsJob>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    executor.jobs.get(&id)?.map(Json).ok_or(Error::NotFound)
}

async fn execute(executor: Arc<Executor>, dispatch: OperationsDispatch) -> Result<()> {
    let intent = &dispatch.intent;
    let id = intent.id.to_string();
    let _guard = executor
        .fleet
        .gate(&intent.command.instance.to_string())
        .await?;
    let Some(current) =
        executor
            .jobs
            .begin(&id, now()?, executor.fleet.closing.load(Ordering::SeqCst))?
    else {
        return Ok(());
    };
    let intent = &current.intent;
    let result = executor.fleet.apply(&intent.command).await;
    let (state, error) = match result {
        Ok(()) => (OperationsJobState::Succeeded, None),
        Err(error) => (OperationsJobState::Failed, Some(error.to_string())),
    };
    let completed = executor.jobs.transition(&id, state, now()?, error)?;
    tracing::info!(job = %id, account = %intent.actor.account, client = ?intent.actor.client, request = %intent.actor.request, state = ?completed.state, "central operation completed");
    Ok(())
}

async fn submit(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Json(dispatch): Json<OperationsDispatch>,
) -> Result<(StatusCode, Json<OperationsJob>)> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    let at = now()?;
    if at >= dispatch.expires_at {
        return Err(Error::Expired);
    }
    if executor.fleet.closing.load(Ordering::SeqCst) {
        return Err(Error::Stopping);
    }
    executor
        .fleet
        .instance(&dispatch.intent.command.instance.to_string())?;
    let (job, fresh) = executor
        .jobs
        .submit(dispatch.intent.clone(), dispatch.expires_at, at)?;
    if fresh {
        tokio::spawn(async move {
            if let Err(error) = execute(executor, dispatch).await {
                tracing::error!(%error, "operation job failed");
            }
        });
    }
    Ok((
        if fresh {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(job),
    ))
}

impl Supervisor {
    pub async fn start(config: Config) -> Result<Self> {
        config.validate()?;
        let credential = config.credential()?;
        let listener = TcpListener::bind(config.bind).await?;
        std::fs::create_dir_all(&config.data)?;
        let lease = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.data.join("supervisor.lock"))?;
        lease.try_lock().map_err(|error| {
            Error::Invalid(format!("supervisor data directory is locked: {error}"))
        })?;
        let jobs = Jobs::open(&config.data.join("operations.sqlite"), now()?)?;
        let fleet = Fleet::start(&config).await?;
        let executor = Arc::new(Executor {
            credential,
            fleet: fleet.clone(),
            jobs,
        });
        let router = Router::new()
            .route(EXECUTOR_SNAPSHOT_PATH, get(snapshot))
            .route(EXECUTOR_JOBS_PATH, post(submit))
            .route(&format!("{EXECUTOR_JOBS_PATH}/{{id}}"), get(job))
            .layer(DefaultBodyLimit::max(OPERATIONS_MAX_REQUEST_BYTES))
            .with_state(executor);
        Ok(Self {
            listener,
            router,
            fleet,
            lease,
        })
    }

    pub fn address(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn run(self, stop: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let serving = axum::serve(self.listener, self.router)
            .with_graceful_shutdown(stop)
            .await;
        self.fleet.close().await;
        serving?;
        drop(self.lease);
        Ok(())
    }
}
