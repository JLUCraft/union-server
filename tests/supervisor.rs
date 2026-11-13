#![cfg(unix)]

use minecraftd::instance::server::DEFAULT_GRACEFUL_STOP_TIMEOUT_SECS;

use federated_server::{
    operation_contracts::{
        OPERATIONS_CLAIM_HEADER, OPERATIONS_LEASE_SECONDS, OPERATIONS_SCOPE_HEADER,
        OperationsAlert, OperationsDispatch, OperationsJob, OperationsJobPage, OperationsJobState,
        OperationsLogPage, OperationsObservation, OperationsSnapshot,
    },
    operations::{Config, Supervisor},
};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    sync::Arc,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

const JOB_WAIT: Duration = Duration::from_secs(DEFAULT_GRACEFUL_STOP_TIMEOUT_SECS + 5);
const JOB_INTERVAL: Duration = Duration::from_millis(20);

async fn completed(
    client: &Client,
    origin: &str,
    credential: &str,
    id: &str,
) -> anyhow::Result<OperationsJob> {
    tokio::time::timeout(JOB_WAIT, async {
        loop {
            let job = client
                .get(format!("{origin}/jobs/{id}"))
                .bearer_auth(credential)
                .send()
                .await?
                .error_for_status()?
                .json::<OperationsJob>()
                .await?;
            if !matches!(
                job.state,
                OperationsJobState::Queued | OperationsJobState::Running
            ) {
                return Ok::<_, anyhow::Error>(job);
            }
            tokio::time::sleep(JOB_INTERVAL).await;
        }
    })
    .await?
}

fn configuration(
    root: &Path,
    credential: &str,
    authority: &str,
) -> anyhow::Result<std::path::PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let key = root.join("credential");
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key)?;
    output.write_all(credential.as_bytes())?;
    let config = root.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "bind":"127.0.0.1:0", "data":root.join("data"), "credential_file":key,"host":"host-a","authority":authority,
            "backups":{"retained":10,"retained_bytes":10485760,"archive_bytes":1048576,"entries":1000,"remote":null},
            "instances":{"stubborn":{"start_command":r#"sh -c 'trap "exit 0" TERM; (trap "" TERM; echo stubborn-ready; exec sleep 60 >/dev/null 2>&1)& wait'"#,"stop_command":"","kind":"service","auto_start":false},"gateway":{"start_command":"cat","stop_command":"","kind":"service","auto_start":false},"world":{"start_command":"sh -c 'echo early-start; cat'","stop_command":"","kind":"bedrock","auto_start":false}}
        }))?,
    )?;
    Ok(config)
}

fn dispatch(id: &str, action: &str) -> anyhow::Result<OperationsDispatch> {
    Ok(serde_json::from_value(json!({
        "intent":{"id":id,"actor":{"account":"administrator","client":"test-agent","request":"test-call"},"scope":"global","command":{"instance":"gateway","operation":{"action":action}}},
        "expiresAt":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()+OPERATIONS_LEASE_SECONDS
    }))?)
}

type Grants = Arc<Mutex<BTreeMap<String, OperationsDispatch>>>;
fn grant(grants: &Grants, dispatch: &OperationsDispatch) -> anyhow::Result<()> {
    grants
        .lock()
        .map_err(|_| anyhow::anyhow!("grants poisoned"))?
        .insert(dispatch.intent.id.to_string(), dispatch.clone());
    Ok(())
}
async fn authority(
    grants: Grants,
    credential: String,
) -> anyhow::Result<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    async fn claim(
        State((grants, credential)): State<(Grants, String)>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Result<Json<OperationsDispatch>, StatusCode> {
        if headers
            .get(OPERATIONS_CLAIM_HEADER)
            .and_then(|value| value.to_str().ok())
            != Some(credential.as_str())
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let id = body
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or(StatusCode::BAD_REQUEST)?;
        grants
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .get(id)
            .cloned()
            .map(Json)
            .ok_or(StatusCode::FORBIDDEN)
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/internal/operations/host-a/claim", post(claim))
        .with_state((grants, credential));
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok((origin, task))
}
#[tokio::test]
async fn supervisor_keeps_authorized_jobs_and_remains_available_when_the_managed_service_stops()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let credential = "a".repeat(64);
    let grants = Arc::new(Mutex::new(BTreeMap::new()));
    let (authority, authority_task) = authority(Arc::clone(&grants), credential.clone()).await?;
    let config = configuration(directory.path(), &credential, &authority)?;
    let supervisor = Supervisor::start(Config::load(&config)?).await?;
    let origin = format!("http://{}", supervisor.address()?);
    let stop = Arc::new(Notify::new());
    let signal = stop.clone();
    let server = tokio::spawn(supervisor.run(async move { signal.notified().await }));
    let client = Client::new();
    assert_eq!(
        client
            .get(format!("{origin}/snapshot"))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let start = dispatch("start-gateway", "start")?;
    grant(&grants, &start)?;
    let submitted = client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&start)
        .send()
        .await?;
    assert_eq!(submitted.status(), StatusCode::ACCEPTED);
    let started = completed(&client, &origin, &credential, "start-gateway").await?;
    assert!(matches!(started.state, OperationsJobState::Succeeded));
    let snapshot = client
        .get(format!("{origin}/snapshot"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsSnapshot>()
        .await?;
    assert!(snapshot.instances[0].pid.is_some());
    let repeated = client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&start)
        .send()
        .await?;
    assert_eq!(repeated.status(), StatusCode::OK);
    let conflict = dispatch("start-gateway", "stop")?;
    assert_eq!(
        client
            .post(format!("{origin}/jobs"))
            .bearer_auth(&credential)
            .json(&conflict)
            .send()
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    let mut world = serde_json::to_value(dispatch("start-world", "start")?)?;
    world["intent"]["command"]["instance"] = "world".into();
    grant(&grants, &serde_json::from_value(world.clone())?)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&world)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "start-world")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));
    world["intent"]["id"] = "console-world".into();
    world["intent"]["command"]["operation"] = json!({"action":"console","input":"say hello"});
    grant(&grants, &serde_json::from_value(world.clone())?)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&world)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "console-world")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));
    let streamed = client
        .get(format!("{origin}/instances/world/logs/watch"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert!(streamed.contains("early-start"));
    assert!(streamed.contains("say hello"));
    assert!(streamed.contains("event: done"));
    let observed = client
        .get(format!("{origin}/instances/world/observe"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsObservation>()
        .await?;
    assert!(observed.instance.pid.is_some());
    assert!(observed.memory_bytes.is_some());
    assert!(observed.cpu_percent.is_none());
    let history = client
        .get(format!("{origin}/instances/world/jobs"))
        .bearer_auth(&credential)
        .header(OPERATIONS_SCOPE_HEADER, "global")
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsJobPage>()
        .await?;
    assert_eq!(history.jobs.len(), 2);
    let mut kill = world.clone();
    kill["intent"]["id"] = "kill-world".into();
    kill["intent"]["command"]["operation"] = json!({"action":"kill","pid":observed.instance.pid});
    kill["approval"] = json!({"account":"administrator","request":"kill-world","approvedAt":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&kill)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "kill-world")
            .await?
            .state,
        OperationsJobState::Failed
    ));
    let mut approved = kill;
    approved["intent"]["id"] = "approved-kill".into();
    approved["approval"]["request"] = "approved-kill".into();
    grant(&grants, &serde_json::from_value(approved.clone())?)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&approved)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "approved-kill")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));

    let mut stubborn = serde_json::to_value(dispatch("start-stubborn", "start")?)?;
    stubborn["intent"]["command"]["instance"] = "stubborn".into();
    grant(&grants, &serde_json::from_value(stubborn.clone())?)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&stubborn)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "start-stubborn")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));
    let mut stream = client
        .get(format!("{origin}/instances/stubborn/logs/watch"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?;
    tokio::time::timeout(JOB_WAIT, async {
        let mut output = String::new();
        while let Some(chunk) = stream.chunk().await? {
            output.push_str(&String::from_utf8_lossy(&chunk));
            if output.contains("stubborn-ready") {
                return Ok::<(), anyhow::Error>(());
            }
        }
        anyhow::bail!("stubborn process output ended");
    })
    .await??;
    drop(stream);
    let owned = client
        .get(format!("{origin}/instances/stubborn/observe"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsObservation>()
        .await?;
    for action in ["stop", "restart"] {
        let id = format!("{action}-stubborn");
        stubborn["intent"]["id"] = id.clone().into();
        stubborn["intent"]["command"]["operation"] = json!({"action":action});
        grant(&grants, &serde_json::from_value(stubborn.clone())?)?;
        client
            .post(format!("{origin}/jobs"))
            .bearer_auth(&credential)
            .json(&stubborn)
            .send()
            .await?
            .error_for_status()?;
        assert!(matches!(
            completed(&client, &origin, &credential, &id).await?.state,
            OperationsJobState::Failed
        ));
        let retained = client
            .get(format!("{origin}/instances/stubborn/observe"))
            .bearer_auth(&credential)
            .send()
            .await?
            .error_for_status()?
            .json::<OperationsObservation>()
            .await?;
        assert_eq!(retained.instance.pid, owned.instance.pid);
        assert!(retained.alerts.contains(&OperationsAlert::ProcessStopped));
        assert!(retained.instance.pid.is_some());
    }
    stubborn["intent"]["id"] = "kill-stubborn".into();
    stubborn["intent"]["command"]["operation"] = json!({"action":"kill","pid":owned.instance.pid});
    stubborn["approval"] = json!({"account":"administrator","request":"kill-stubborn","approvedAt":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    grant(&grants, &serde_json::from_value(stubborn.clone())?)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&stubborn)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "kill-stubborn")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));

    let stop_job = dispatch("stop-gateway", "stop")?;
    grant(&grants, &stop_job)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(&credential)
        .json(&stop_job)
        .send()
        .await?
        .error_for_status()?;
    assert!(matches!(
        completed(&client, &origin, &credential, "stop-gateway")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));
    let snapshot = client
        .get(format!("{origin}/snapshot"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsSnapshot>()
        .await?;
    assert!(snapshot.instances[0].pid.is_none());
    stop.notify_one();
    server.await??;

    let supervisor = Supervisor::start(Config::load(&config)?).await?;
    let origin = format!("http://{}", supervisor.address()?);
    let signal = stop.clone();
    let server = tokio::spawn(supervisor.run(async move { signal.notified().await }));
    assert!(matches!(
        completed(&client, &origin, &credential, "start-gateway")
            .await?
            .state,
        OperationsJobState::Succeeded
    ));
    let logs = client
        .get(format!("{origin}/instances/world/logs"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsLogPage>()
        .await?;
    assert!(
        logs.entries
            .iter()
            .any(|entry| entry.data.contains("say hello"))
    );
    stop.notify_one();
    server.await??;
    authority_task.abort();
    Ok(())
}

async fn perform(
    client: &Client,
    origin: &str,
    credential: &str,
    grants: &Grants,
    id: &str,
    operation: serde_json::Value,
    approved: bool,
) -> anyhow::Result<OperationsJob> {
    let mut value = serde_json::to_value(dispatch(id, "start")?)?;
    value["intent"]["command"]["operation"] = operation;
    if approved {
        value["approval"] = json!({"account":"administrator","request":id,"approvedAt":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()});
    }
    let value: OperationsDispatch = serde_json::from_value(value)?;
    grant(grants, &value)?;
    client
        .post(format!("{origin}/jobs"))
        .bearer_auth(credential)
        .json(&value)
        .send()
        .await?
        .error_for_status()?;
    completed(client, origin, credential, id).await
}

#[tokio::test]
async fn scoped_backups_survive_encrypted_transfer_and_transactional_restore() -> anyhow::Result<()>
{
    use age::secrecy::ExposeSecret;
    use axum::{
        Router,
        body::Bytes,
        extract::{Path as RoutePath, State},
        http::HeaderMap,
        routing::get,
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, Ordering};
    type Objects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;
    type Storage = (Objects, Arc<AtomicBool>);
    async fn download(
        State((objects, _reject)): State<Storage>,
        headers: HeaderMap,
        RoutePath(id): RoutePath<String>,
    ) -> Result<Vec<u8>, StatusCode> {
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer fixture-storage-key")
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        objects
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .get(&id)
            .cloned()
            .ok_or(StatusCode::NOT_FOUND)
    }
    async fn upload(
        State((objects, reject)): State<Storage>,
        headers: HeaderMap,
        RoutePath(id): RoutePath<String>,
        body: Bytes,
    ) -> Result<StatusCode, StatusCode> {
        if headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some("Bearer fixture-storage-key")
        {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if reject.load(Ordering::SeqCst) {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        objects
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .insert(id, body.to_vec());
        Ok(StatusCode::NO_CONTENT)
    }
    let directory = tempfile::tempdir()?;
    let credential = "3".repeat(64);
    let grants = Arc::new(Mutex::new(BTreeMap::new()));
    let (authority, authority_task) = authority(Arc::clone(&grants), credential.clone()).await?;
    let objects: Objects = Arc::new(Mutex::new(BTreeMap::new()));
    let reject_upload = Arc::new(AtomicBool::new(true));
    let storage = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let storage_origin = format!("http://{}", storage.local_addr()?);
    let storage_router = Router::new()
        .route("/backups/{id}", get(download).put(upload))
        .with_state((Arc::clone(&objects), Arc::clone(&reject_upload)));
    let storage_task = tokio::spawn(async move { axum::serve(storage, storage_router).await });
    let key = age::x25519::Identity::generate();
    let private = directory.path().join("backup.identity");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&private)?
        .write_all(key.to_string().expose_secret().as_bytes())?;
    let storage_credential = directory.path().join("backup.credential");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&storage_credential)?
        .write_all(b"fixture-storage-key")?;
    let config = configuration(directory.path(), &credential, &authority)?;
    let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&config)?)?;
    value["backups"]["retained"] = 2.into();
    value["backups"]["remote"] = json!({"endpoint":storage_origin,"credential_file":storage_credential,"recipient":key.to_public().to_string(),"identity_file":private});
    value["instances"] = json!({"gateway":{"start_command":r#"sh -c 'while read line; do if [ "$line" = stop ]; then if [ -f reject-stop ]; then rm reject-stop; exit 23; fi; echo saved >> world/data; exit 0; fi; done'"#,"stop_command":"stop","kind":"bedrock","auto_start":false}});
    std::fs::write(&config, serde_json::to_vec(&value)?)?;
    let world = directory.path().join("data/instances/gateway/world");
    std::fs::create_dir_all(world.join("empty"))?;
    std::fs::write(world.join("data"), b"initial\n")?;
    std::fs::set_permissions(world.join("data"), std::fs::Permissions::from_mode(0o600))?;
    let supervisor = Supervisor::start(Config::load(&config)?).await?;
    let origin = format!("http://{}", supervisor.address()?);
    let stop = Arc::new(Notify::new());
    let signal = Arc::clone(&stop);
    let supervisor_task = tokio::spawn(supervisor.run(async move { signal.notified().await }));
    let client = Client::new();
    let started = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-start",
        json!({"action":"start"}),
        false,
    )
    .await?;
    assert!(matches!(started.state, OperationsJobState::Succeeded));
    let created = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-create",
        json!({"action":"backup","label":"consistent world"}),
        false,
    )
    .await?;
    assert!(
        matches!(created.state, OperationsJobState::Succeeded),
        "{:?}",
        created.error
    );
    let archive = created
        .result
        .ok_or_else(|| anyhow::anyhow!("backup result missing"))?
        .backup
        .ok_or_else(|| anyhow::anyhow!("archive missing"))?
        .id
        .to_string();
    let failed_export = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-export-failed",
        json!({"action":"backup_export","archive":archive}),
        false,
    )
    .await?;
    assert!(matches!(failed_export.state, OperationsJobState::Failed));
    assert!(
        std::fs::read_dir(directory.path().join("data/transfers"))?
            .next()
            .transpose()?
            .is_none()
    );
    reject_upload.store(false, Ordering::SeqCst);
    let exported = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-export",
        json!({"action":"backup_export","archive":archive}),
        false,
    )
    .await?;
    assert!(
        matches!(exported.state, OperationsJobState::Succeeded),
        "{:?}",
        exported.error
    );
    assert_eq!(
        objects
            .lock()
            .map_err(|_| anyhow::anyhow!("objects poisoned"))?
            .len(),
        1
    );
    let deleted = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-delete",
        json!({"action":"backup_delete","archive":archive}),
        true,
    )
    .await?;
    assert!(
        matches!(deleted.state, OperationsJobState::Succeeded),
        "{:?}",
        deleted.error
    );
    rusqlite::Connection::open(directory.path().join("data/operations.sqlite"))?.execute(
        "INSERT INTO backup_owners VALUES(?,?,?)",
        rusqlite::params![archive, "gateway", "club:another"],
    )?;
    let imported = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-import",
        json!({"action":"backup_import","archive":archive}),
        false,
    )
    .await?;
    assert!(
        matches!(imported.state, OperationsJobState::Succeeded),
        "{:?}",
        imported.error
    );
    let other = client
        .get(format!("{origin}/instances/gateway/backups"))
        .bearer_auth(&credential)
        .header(OPERATIONS_SCOPE_HEADER, "club:another")
        .send()
        .await?
        .error_for_status()?
        .json::<federated_server::operation_contracts::OperationsBackupPage>()
        .await?;
    assert!(other.backups.is_empty());
    std::fs::write(world.join("data"), b"changed\n")?;
    std::fs::write(world.join("obsolete"), b"old-only")?;
    let preparation = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "restore-preparation",
        json!({"action":"restore_prepare","archive":archive}),
        false,
    )
    .await?;
    assert!(
        matches!(preparation.state, OperationsJobState::Succeeded),
        "{:?}",
        preparation.error
    );
    let prepared_state = client
        .get(format!("{origin}/snapshot"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsSnapshot>()
        .await?;
    assert!(matches!(
        prepared_state.instances[0].state,
        federated_server::operation_contracts::OperationsInstanceState::Running
    ));
    std::fs::write(world.join("data"), b"latest\n")?;
    let denied = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "restore-denied",
        json!({"action":"restore","archive":archive,"preparation":"restore-preparation"}),
        false,
    )
    .await?;
    assert!(matches!(denied.state, OperationsJobState::Failed));
    assert_eq!(std::fs::read(world.join("data"))?, b"latest\n");
    std::fs::write(
        world
            .parent()
            .ok_or_else(|| anyhow::anyhow!("world parent missing"))?
            .join("reject-stop"),
        b"reject",
    )?;
    let unclean = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "restore-unclean",
        json!({"action":"restore","archive":archive,"preparation":"restore-preparation"}),
        true,
    )
    .await?;
    assert!(matches!(unclean.state, OperationsJobState::Failed));
    assert_eq!(std::fs::read(world.join("data"))?, b"latest\n");
    let restored = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "restore-approved",
        json!({"action":"restore","archive":archive,"preparation":"restore-preparation"}),
        true,
    )
    .await?;
    assert!(
        matches!(restored.state, OperationsJobState::Succeeded),
        "{:?}",
        restored.error
    );
    let safety = restored
        .result
        .and_then(|result| result.safety_archive)
        .ok_or_else(|| anyhow::anyhow!("safety archive missing"))?
        .to_string();
    assert_eq!(std::fs::read(world.join("data"))?, b"initial\nsaved\n");
    assert!(!world.join("obsolete").try_exists()?);
    assert!(world.join("empty").is_dir());
    assert_eq!(
        std::fs::metadata(world.join("data"))?.permissions().mode() & 0o777,
        0o600
    );
    let rollback_preparation = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "rollback-preparation",
        json!({"action":"restore_prepare","archive":safety}),
        false,
    )
    .await?;
    assert!(
        matches!(rollback_preparation.state, OperationsJobState::Succeeded),
        "{:?}",
        rollback_preparation.error
    );
    let rollback = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "restore-rollback",
        json!({"action":"restore","archive":safety,"preparation":"rollback-preparation"}),
        true,
    )
    .await?;
    assert!(
        matches!(rollback.state, OperationsJobState::Succeeded),
        "{:?}",
        rollback.error
    );
    assert_eq!(std::fs::read(world.join("data"))?, b"latest\nsaved\n");
    assert_eq!(std::fs::read(world.join("obsolete"))?, b"old-only");
    let retained = client
        .get(format!("{origin}/instances/gateway/backups"))
        .bearer_auth(&credential)
        .header(OPERATIONS_SCOPE_HEADER, "global")
        .send()
        .await?
        .error_for_status()?
        .json::<federated_server::operation_contracts::OperationsBackupPage>()
        .await?;
    assert_eq!(retained.backups.len(), 2);
    std::fs::write(world.join("oversized"), vec![0u8; 2 * 1024 * 1024])?;
    let oversized = perform(
        &client,
        &origin,
        &credential,
        &grants,
        "backup-over-quota",
        json!({"action":"backup","label":"oversized"}),
        false,
    )
    .await?;
    assert!(matches!(oversized.state, OperationsJobState::Failed));
    let snapshot = client
        .get(format!("{origin}/snapshot"))
        .bearer_auth(&credential)
        .send()
        .await?
        .error_for_status()?
        .json::<OperationsSnapshot>()
        .await?;
    assert!(matches!(
        snapshot.instances[0].state,
        federated_server::operation_contracts::OperationsInstanceState::Running
    ));
    stop.notify_one();
    supervisor_task.await??;
    authority_task.abort();
    storage_task.abort();
    Ok(())
}
