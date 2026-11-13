use super::{Config, Error, Result, fleet::Fleet, jobs::Jobs, now};
use crate::{
    bearer::require_bearer,
    operation_contracts::{
        EXECUTOR_INSTANCES_PATH, EXECUTOR_JOBS_PATH, EXECUTOR_SNAPSHOT_PATH,
        OPERATIONS_MAX_PAGE_ROWS, OPERATIONS_MAX_REQUEST_BYTES, OPERATIONS_SCOPE_HEADER,
        OPERATIONS_WATCH_SECONDS, OperationsCancellation, OperationsDispatch, OperationsJob,
        OperationsJobPage, OperationsJobState, OperationsLogPage, OperationsPageQuery,
        OperationsSnapshot,
    },
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, Sse, sse::Event},
    routing::{get, post},
};
use std::{
    fs::File,
    future::Future,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;

struct Executor {
    credential: Vec<u8>,
    fleet: Arc<Fleet>,
    jobs: Arc<Jobs>,
    observer: Arc<super::observe::Observer>,
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

fn page_size(query: &OperationsPageQuery) -> usize {
    query
        .limit
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or(OPERATIONS_MAX_PAGE_ROWS)
        .clamp(1, OPERATIONS_MAX_PAGE_ROWS)
}
fn page_cursor(query: &OperationsPageQuery, default: i64) -> Result<i64> {
    query
        .cursor
        .as_ref()
        .map(|cursor| {
            cursor
                .to_string()
                .parse::<i64>()
                .map_err(|_| Error::Invalid("invalid cursor".into()))
        })
        .unwrap_or(Ok(default))
}
async fn history(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(instance): Path<String>,
    Query(query): Query<OperationsPageQuery>,
) -> Result<Json<OperationsJobPage>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;

    let scope = headers
        .get(OPERATIONS_SCOPE_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| Error::Invalid("scope required".into()))?;
    executor.fleet.instance(&instance)?;
    Ok(Json(executor.jobs.history(
        &instance,
        scope,
        page_cursor(&query, i64::MAX)?,
        page_size(&query),
    )?))
}
async fn cancel(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<OperationsCancellation>,
) -> Result<Json<OperationsJob>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    let at = now()?;
    if at >= request.expires_at {
        return Err(Error::Expired);
    }
    Ok(Json(executor.jobs.cancel(&id, request.actor, at)?))
}
async fn output(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(instance): Path<String>,
    Query(query): Query<OperationsPageQuery>,
) -> Result<Json<OperationsLogPage>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    executor.fleet.instance(&instance)?;
    Ok(Json(executor.jobs.output(
        &instance,
        page_cursor(&query, 0)?,
        page_size(&query),
    )?))
}
async fn observe(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(instance): Path<String>,
) -> Result<Json<crate::operation_contracts::OperationsObservation>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    let managed = executor.fleet.instance(&instance)?;
    let idle = managed.gate.clone().try_lock_owned().ok();
    let expected = idle.is_some() && managed.expected_running.load(Ordering::SeqCst);
    let failed = managed.health.failed.load(Ordering::SeqCst);
    let lost = managed.health.lost.load(Ordering::SeqCst);
    let snapshot = executor.fleet.snapshot().await?;
    let observer = Arc::clone(&executor.observer);
    let root = executor.fleet.root.clone();
    let observation = tokio::task::spawn_blocking(move || {
        observer.observe(&root, snapshot, &instance, expected, failed, lost)
    })
    .await??;
    drop(idle);
    Ok(Json(observation))
}
const OUTPUT_POLL_INTERVAL: Duration = Duration::from_millis(200);
async fn watch_output(
    State(executor): State<Arc<Executor>>,
    headers: HeaderMap,
    Path(instance): Path<String>,
    Query(query): Query<OperationsPageQuery>,
) -> Result<Sse<impl futures::Stream<Item = std::result::Result<Event, std::io::Error>>>> {
    require_bearer(&headers, &executor.credential).map_err(|_| Error::Unauthorized)?;
    executor.fleet.instance(&instance)?;
    let cursor = page_cursor(&query, 0)?;
    let limit = page_size(&query);
    let deadline = Instant::now() + Duration::from_secs(OPERATIONS_WATCH_SECONDS);
    let stream = futures::stream::unfold(
        (executor, instance, cursor, deadline, true, false),
        move |(executor, instance, cursor, deadline, first, finished)| async move {
            if finished {
                return None;
            }
            if !first {
                tokio::time::sleep(OUTPUT_POLL_INTERVAL).await;
            }
            let done = Instant::now() >= deadline;
            match executor.jobs.output(&instance, cursor, limit) {
                Ok(page) => {
                    let next = page
                        .cursor
                        .to_string()
                        .parse::<i64>()
                        .map_err(std::io::Error::other);
                    let event = if done {
                        Event::default().event("done").json_data(&page)
                    } else if !first && page.entries.is_empty() {
                        Ok(Event::default().comment("keepalive"))
                    } else {
                        Event::default().event("logs").json_data(&page)
                    };
                    match (next, event) {
                        (Ok(next), Ok(event)) => {
                            Some((Ok(event), (executor, instance, next, deadline, false, done)))
                        }
                        (Err(error), _) => Some((
                            Err(error),
                            (executor, instance, cursor, deadline, false, true),
                        )),
                        (_, Err(error)) => Some((
                            Err(std::io::Error::other(error)),
                            (executor, instance, cursor, deadline, false, true),
                        )),
                    }
                }
                Err(error) => Some((
                    Err(std::io::Error::other(error)),
                    (executor, instance, cursor, deadline, false, true),
                )),
            }
        },
    );
    Ok(Sse::new(stream))
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
        let jobs = Arc::new(Jobs::open(&config.data.join("operations.sqlite"), now()?)?);
        let fleet = Fleet::start(&config, &jobs).await?;
        let executor = Arc::new(Executor {
            credential,
            fleet: fleet.clone(),
            jobs,
            observer: Arc::new(super::observe::Observer::new()),
        });
        let router = Router::new()
            .route(EXECUTOR_SNAPSHOT_PATH, get(snapshot))
            .route(EXECUTOR_JOBS_PATH, post(submit))
            .route(&format!("{EXECUTOR_JOBS_PATH}/{{id}}"), get(job))
            .route(&format!("{EXECUTOR_JOBS_PATH}/{{id}}/cancel"), post(cancel))
            .route(
                &format!("{EXECUTOR_INSTANCES_PATH}/{{instance}}/jobs"),
                get(history),
            )
            .route(
                &format!("{EXECUTOR_INSTANCES_PATH}/{{instance}}/observe"),
                get(observe),
            )
            .route(
                &format!("{EXECUTOR_INSTANCES_PATH}/{{instance}}/logs"),
                get(output),
            )
            .route(
                &format!("{EXECUTOR_INSTANCES_PATH}/{{instance}}/logs/watch"),
                get(watch_output),
            )
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
        self.fleet.close().await?;
        serving?;
        drop(self.lease);
        Ok(())
    }
}
