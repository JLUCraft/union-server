use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use federated_server::runtime::{Config, Host};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
const SESSION: &str = "host-session-token-abcdefghijklmnopqrstuvwxyz";
const PAPER: &str = "paper-token-for-runtime-abcdefghijklmnopqrstuvwxyz";
#[derive(Clone, Default)]
struct Station(Arc<Mutex<Vec<Value>>>);
fn authorize(headers: &HeaderMap) -> std::result::Result<(), StatusCode> {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {SESSION}"))
    {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
async fn action(
    State(station): State<Station>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    authorize(&headers)?;
    station.0.lock().await.push(body);
    Ok(Json(json!({})))
}
async fn delivery(
    State(station): State<Station>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    authorize(&headers)?;
    station.0.lock().await.push(body.clone());
    Ok(Json(
        json!({"id":"activity-receipt", "attestation":{"source":body["source"],"windowStartMs":body["windowStartMs"],"windowEndMs":body["windowEndMs"],"players":body["players"],"evidence":"private-artifact"}, "creditedAt":0,"creditedDay":0,"accounts":{},"awarded":{}}),
    ))
}
async fn sources(headers: HeaderMap) -> std::result::Result<Json<Value>, StatusCode> {
    authorize(&headers)?;
    Ok(Json(
        json!({"sources":[{"config":{"id":"activity", "title":"Activity", "club":"jlu", "account":"host", "resource":"arena", "weightBps":10000, "pointsPerSlice":"1", "maxBonusPerSlice":"0", "dailySourceCap":"100", "enabled":true}, "lastWindowEndMs":0}]}),
    ))
}
fn private(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn write(path: &Path, value: &Value) -> Result<()> {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
#[tokio::test]
async fn central_host_delivers_reports_drains_on_close_and_recovers_from_partial_start_failure()
-> Result<()> {
    let station = Station::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let router = Router::new()
        .route("/api/leagues/cup/actions", post(action))
        .route("/api/hosted-activity-sources", get(sources))
        .route("/api/points/activity-deliveries", post(delivery))
        .route(
            "/api/leagues/denied/actions",
            post(|| async { StatusCode::FORBIDDEN }),
        )
        .with_state(station.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    private(&base.join("host.session"), SESSION)?;
    private(&base.join("paper.token"), PAPER)?;
    private(&base.join("paper.secret"), &"s".repeat(32))?;
    let path = base.join("host.json");
    let mut value = json!({"services":{
        "scoring":{"bind":"127.0.0.1:0","skin_site":origin,"session_token":"host.session","token":"paper.token"},
        "activity_oracle":{"bind":"127.0.0.1:0","skin_site":origin,"session_token":"host.session","spool":"pending.json","probes":[{"source":"activity","resource":"arena","token":"paper.token"}]}
    }});
    write(&path, &value)?;
    let config = Config::load(&path)?;
    assert_eq!(
        config.services.scoring.as_ref().unwrap().session_token,
        base.join("host.session")
    );
    assert_eq!(
        config.services.activity_oracle.as_ref().unwrap().spool,
        base.join("pending.json")
    );
    let host = Host::start(config).await?;
    let status = host.status();
    assert_eq!(status.services.len(), 2);
    let client = reqwest::Client::builder().no_proxy().build()?;
    let score = format!("http://{}/v1/score", status.services["scoring"]);
    let payload =
        json!({"league":"cup","event":"measured","players":{"account-alice":10},"teams":{}});
    assert_eq!(
        client.post(&score).json(&payload).send().await?.status(),
        401
    );
    assert_eq!(
        client
            .post(&score)
            .bearer_auth(PAPER)
            .json(&payload)
            .send()
            .await?
            .status(),
        204
    );
    let contract: Value = serde_json::from_str(include_str!(
        "../../federated-skinstation/shared/contracts/points.schema.json"
    ))?;
    let slice = contract["definitions"]["ActivityLimits"]["properties"]["sliceMs"]["const"]
        .as_u64()
        .unwrap();
    let end = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64 / slice * slice;
    let report = json!({"window_start_ms":end-slice,"window_end_ms":end,"players":{}});
    let endpoint = format!(
        "http://{}/v1/activity/activity/slice",
        status.services["activity_oracle"]
    );
    assert_eq!(
        client
            .post(endpoint)
            .bearer_auth(PAPER)
            .json(&report)
            .send()
            .await?
            .status(),
        204
    );
    assert_eq!(station.0.lock().await.len(), 1);
    host.close().await?;
    let captured = station.0.lock().await;
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0]["players"], payload["players"]);
    assert_eq!(captured[1]["source"], "activity");
    assert_eq!(captured[1]["windowEndMs"], end);
    let proof: Value = serde_json::from_str(captured[1]["telemetry"].as_str().unwrap())?;
    assert_eq!(proof["slices"][0]["report"], report);
    drop(captured);
    // The scoring listener starts before a later activity startup failure.
    value["services"]["scoring"]["bind"] = status.services["scoring"].to_string().into();
    value["services"]["activity_oracle"]["bind"] =
        status.services["activity_oracle"].to_string().into();
    value["services"]["activity_oracle"]["spool"] = "missing/pending.json".into();
    write(&path, &value)?;
    assert!(matches!(
        Host::start(Config::load(&path)?).await,
        Err(federated_server::Error::Service {
            service: "activity_oracle",
            ..
        })
    ));
    value["services"]["activity_oracle"]["spool"] = "pending.json".into();
    write(&path, &value)?;
    let recovered = Host::start(Config::load(&path)?).await?;
    assert_eq!(
        client
            .post(&score)
            .bearer_auth(PAPER)
            .json(&payload)
            .send()
            .await?
            .status(),
        204
    );
    recovered.close().await?;
    // A real central denial ends the native service and wakes the host supervisor.
    value = json!({"services":{"league_proxy":{"config":{
        "league":"denied", "bind":"127.0.0.1:0", "transfer":{"host":"game.test","port":25565},
        "waiting":{"address":"127.0.0.1:25566","forwarding_secret":"paper.secret"},
        "arena":{"address":"127.0.0.1:25567","forwarding_secret":"paper.secret"},
        "skin_site":origin,"session_token":"host.session"
    }}}});
    write(&path, &value)?;
    let denied = Host::start(Config::load(&path)?).await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), denied.run()).await?,
        Err(federated_server::Error::ServiceStopped("league_proxy"))
    ));
    assert!(matches!(
        denied.close().await,
        Err(federated_server::Error::Service {
            service: "league_proxy",
            ..
        })
    ));
    server.abort();
    let _ = server.await;
    Ok(())
}
