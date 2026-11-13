#![cfg(unix)]

use federated_server::{
    operation_contracts::{
        OPERATIONS_LEASE_SECONDS, OPERATIONS_SCOPE_HEADER, OperationsDispatch, OperationsJob,
        OperationsJobPage, OperationsJobState, OperationsLogPage, OperationsObservation,
        OperationsSnapshot,
    },
    operations::{Config, Supervisor},
};
use reqwest::{Client, StatusCode};
use serde_json::json;
use std::{
    io::Write,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

const JOB_WAIT: Duration = Duration::from_secs(5);
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

fn configuration(root: &Path, credential: &str) -> anyhow::Result<std::path::PathBuf> {
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
            "bind":"127.0.0.1:0", "data":root.join("data"), "credential_file":key,
            "instances":{"gateway":{"start_command":"cat","stop_command":"","kind":"service","auto_start":false},"world":{"start_command":"sh -c 'echo early-start; cat'","stop_command":"","kind":"bedrock","auto_start":false}}
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

#[tokio::test]
async fn supervisor_keeps_authorized_jobs_and_remains_available_when_the_managed_service_stops()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let credential = "a".repeat(64);
    let config = configuration(directory.path(), &credential)?;
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
    let stop_job = dispatch("stop-gateway", "stop")?;
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
    Ok(())
}
