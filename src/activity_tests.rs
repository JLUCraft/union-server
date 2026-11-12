use super::*;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinSet;
const TOKEN: &str = "activity-paper-token-abcdefghijklmnopqrstuvwxyz";
const PROFILE: &str = "0000000000000000000000000000002a";
fn metrics() -> ActivityMetrics {
    ActivityMetrics {
        movement_steps: 20,
        distinct_positions: 8,
        look_samples: 12,
        yaw_variance_milli: 100_000,
        pitch_variance_milli: 0,
        world_interactions: 3,
        progress_events: 0,
    }
}
#[test]
fn idle_fixed_view_and_two_position_loops_fail_the_activity_predicate() {
    let mut value = metrics();
    assert!(value.active());
    value.yaw_variance_milli = 0;
    assert!(!value.active());
    value = metrics();
    value.distinct_positions = 2;
    assert!(!value.active());
    value = metrics();
    value.world_interactions = 0;
    assert!(!value.active());
    value.progress_events = 2;
    assert!(value.active());
}
#[test]
fn packets_from_a_later_slice_cannot_fill_a_silent_earlier_gateway_window() {
    let witnesses = Witnesses::default();
    let guard = witnesses
        .begin_at("service", "00000000000000000000000000000001", "account", 0)
        .unwrap();
    guard.touch_at(2 * ACTIVITY_SLICE_MS - 1);
    assert!(
        witnesses
            .covering(
                "service",
                "00000000000000000000000000000001",
                0,
                ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS
            )
            .unwrap()
            .is_none()
    );
    assert!(
        witnesses
            .covering(
                "service",
                "00000000000000000000000000000001",
                ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS,
                2 * ACTIVITY_SLICE_MS
            )
            .unwrap()
            .is_some()
    );
}

#[derive(Clone)]
struct Station {
    token: Arc<tokio::sync::Mutex<String>>,
    enabled: Arc<AtomicBool>,
    lose_reply: Arc<AtomicBool>,
    reject_delivery: Arc<AtomicBool>,
    owns_profile: Arc<AtomicBool>,
    receipts: Arc<tokio::sync::Mutex<BTreeMap<String, (Value, Value)>>>,
}
impl Station {
    async fn authorize(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        crate::bearer::require_bearer(headers, self.token.lock().await.as_bytes())
    }
}
async fn assignments(
    State(state): State<Station>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    state.authorize(&headers).await?;
    let cursor = state
        .receipts
        .lock()
        .await
        .values()
        .map(|(delivery, _)| delivery["windowEndMs"].as_u64().unwrap())
        .max()
        .unwrap_or(0);
    Ok(Json(
        json!({"sources": if state.enabled.load(Ordering::SeqCst) { vec![json!({"config": {"id":"survival", "title":"World", "club":"jlu", "account":"host", "resource":"world", "weightBps":10000, "pointsPerSlice":"10", "maxBonusPerSlice":"0", "dailySourceCap":"1000", "enabled":true}, "lastWindowEndMs":cursor})] } else {vec![]} }),
    ))
}
async fn delivery(
    State(state): State<Station>,
    headers: HeaderMap,
    Json(delivery): Json<ActivityDelivery>,
) -> Result<Json<Value>, StatusCode> {
    state.authorize(&headers).await?;
    if !state.enabled.load(Ordering::SeqCst) {
        return Err(StatusCode::FORBIDDEN);
    }
    if state.reject_delivery.load(Ordering::SeqCst) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = format!(
        "{}:{}:{}",
        delivery.source.as_str(),
        delivery.window_start_ms,
        delivery.window_end_ms
    );
    let input = serde_json::to_value(&delivery).unwrap();
    let mut receipts = state.receipts.lock().await;
    if let Some((previous, receipt)) = receipts.get(&id) {
        if previous != &input {
            return Err(StatusCode::CONFLICT);
        }
        return Ok(Json(receipt.clone()));
    }
    if !delivery.profiles.is_empty() && !state.owns_profile.load(Ordering::SeqCst) {
        return Err(StatusCode::FORBIDDEN);
    }
    let receipt = json!({"id":id, "attestation":{"source":delivery.source,"windowStartMs":delivery.window_start_ms,"windowEndMs":delivery.window_end_ms,"players":delivery.players,"evidence":format!("artifact-{}", receipts.len())}, "creditedAt":0, "creditedDay":0, "accounts":{}, "awarded":{}});
    receipts.insert(id, (input, receipt.clone()));
    if state.lose_reply.swap(false, Ordering::SeqCst) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(receipt))
}
async fn artifact(
    State(state): State<Station>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    state.authorize(&headers).await?;
    let receipts = state.receipts.lock().await;
    let (delivery, _) = receipts
        .values()
        .find(|(_, receipt)| receipt["attestation"]["evidence"] == id)
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(
        json!({"profiles":delivery["profiles"],"telemetry":delivery["telemetry"]}),
    ))
}
struct Fixture {
    directory: tempfile::TempDir,
    site: SkinSite,
    station: Station,
    tasks: JoinSet<()>,
}
fn private(path: &std::path::Path, value: &str) -> Result<()> {
    std::fs::write(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let token = "central-host-session-abcdefghijklmnopqrstuvwxyz".to_string();
        private(&directory.path().join("host.session"), &token)?;
        private(&directory.path().join("paper.token"), TOKEN)?;
        let station = Station {
            token: Arc::new(tokio::sync::Mutex::new(token)),
            enabled: Arc::new(AtomicBool::new(true)),
            lose_reply: Arc::new(AtomicBool::new(false)),
            reject_delivery: Arc::new(AtomicBool::new(false)),
            owns_profile: Arc::new(AtomicBool::new(true)),
            receipts: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let site = SkinSite::try_from(format!("http://{}", listener.local_addr()?))?;
        let router = Router::new()
            .route("/api/hosted-activity-sources", get(assignments))
            .route("/api/points/activity-deliveries", post(delivery))
            .route("/api/artifacts/{id}/content", get(artifact))
            .with_state(station.clone());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Ok(Self {
            directory,
            site,
            station,
            tasks,
        })
    }
    fn config(&self) -> Config {
        Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            skin_site: self.site.clone(),
            session_token: self.directory.path().join("host.session"),
            spool: self.directory.path().join("pending.json"),
            probes: vec![Probe {
                source: "survival".into(),
                resource: "world".into(),
                token: self.directory.path().join("paper.token"),
            }],
        }
    }
}
async fn send(
    client: &reqwest::Client,
    oracle: &RunningOracle,
    operation: &str,
    body: Option<&ProbeReport>,
    token: &str,
) -> Result<u16> {
    let mut request = client
        .post(format!(
            "http://{}/v1/activity/survival/{operation}",
            oracle.address()
        ))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(body);
    }
    Ok(request.send().await?.status().as_u16())
}
// A separate runtime lets a simulated process crash cancel every HTTP connection
// task, including keepalive connections holding the router and spool lock.
struct RunningOracle {
    address: SocketAddr,
    control: tokio::sync::oneshot::Sender<bool>,
    thread: std::thread::JoinHandle<Result<()>>,
}
impl RunningOracle {
    async fn start(config: Config, witnesses: Witnesses) -> Result<Self> {
        let (ready, address) = tokio::sync::oneshot::channel();
        let (control, command) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let oracle = Oracle::start(config, witnesses).await?;
                let _ = ready.send(oracle.address());
                if command.await.unwrap_or(false) {
                    oracle.stop().await?;
                }
                // Runtime destruction cancels the server and its connection tasks.
                Ok(())
            })
        });
        Ok(Self {
            address: address.await?,
            control,
            thread,
        })
    }
    fn address(&self) -> SocketAddr {
        self.address
    }
    async fn finish(self, graceful: bool) -> Result<()> {
        let _ = self.control.send(graceful);
        tokio::task::spawn_blocking(move || self.thread.join())
            .await?
            .map_err(|_| anyhow::anyhow!("adapter thread panicked"))??;
        Ok(())
    }
}
fn report(start: u64, active: bool) -> ProbeReport {
    let mut measured = metrics();
    if !active {
        measured.look_samples = 0;
    }
    ProbeReport {
        window_start_ms: start,
        window_end_ms: start + ACTIVITY_SLICE_MS,
        players: [
            (PROFILE.into(), measured),
            ("000000000000000000000000000000ff".into(), metrics()),
        ]
        .into(),
    }
}
#[tokio::test]
async fn central_delivery_preserves_gateway_proofs_through_crashes_uncertain_commit_and_revocation()
-> Result<()> {
    let mut fixture = Fixture::new().await?;
    let client = reqwest::Client::builder().no_proxy().build()?;
    let end = now_ms()? / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
    let start = end - 8 * ACTIVITY_SLICE_MS;
    let witnesses = Witnesses::default();
    let guard = witnesses.begin_at("world", PROFILE, "account-alice", start)?;
    guard.touch_at(start + ACTIVITY_SLICE_MS - 1);
    guard.touch_at(start + 2 * ACTIVITY_SLICE_MS - 1);
    let first = report(start, true);
    let second = report(start + ACTIVITY_SLICE_MS, false);
    let oracle = RunningOracle::start(fixture.config(), witnesses).await?;
    assert_eq!(
        send(&client, &oracle, "slice", Some(&first), "wrong-token").await?,
        401
    );
    assert_eq!(
        send(&client, &oracle, "slice", Some(&first), TOKEN).await?,
        204
    );
    assert_eq!(
        send(&client, &oracle, "slice", Some(&second), TOKEN).await?,
        204
    );
    assert!(fixture.station.receipts.lock().await.is_empty());
    oracle.finish(false).await?;
    drop(guard);
    let oracle = RunningOracle::start(fixture.config(), Witnesses::default()).await?;
    fixture
        .station
        .reject_delivery
        .store(true, Ordering::SeqCst);
    assert_eq!(send(&client, &oracle, "flush", None, TOKEN).await?, 400);
    // Failure of the frozen older batch must not quarantine a new Paper report.
    let next = report(start + 2 * ACTIVITY_SLICE_MS, true);
    assert_eq!(
        send(&client, &oracle, "slice", Some(&next), TOKEN).await?,
        503
    );
    fixture
        .station
        .reject_delivery
        .store(false, Ordering::SeqCst);
    fixture.station.lose_reply.store(true, Ordering::SeqCst);
    assert_eq!(send(&client, &oracle, "flush", None, TOKEN).await?, 503);
    assert_eq!(fixture.station.receipts.lock().await.len(), 1);
    fixture.station.owns_profile.store(false, Ordering::SeqCst);
    oracle.finish(false).await?;
    let rotated = "renewed-central-session-abcdefghijklmnopqrstuvwxyz";
    private(&fixture.directory.path().join("host.session"), rotated)?;
    *fixture.station.token.lock().await = rotated.into();
    let oracle = RunningOracle::start(fixture.config(), Witnesses::default()).await?;
    assert_eq!(send(&client, &oracle, "flush", None, TOKEN).await?, 204);
    assert_eq!(
        send(&client, &oracle, "slice", Some(&first), TOKEN).await?,
        204
    );
    let (delivery, receipt) = fixture
        .station
        .receipts
        .lock()
        .await
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(
        delivery["players"],
        json!({"account-alice":{"activeSlices":1,"afkSlices":1,"bonusPoints":"0"}})
    );
    assert_eq!(delivery["profiles"], json!({PROFILE:"account-alice"}));
    let proof: Proof = serde_json::from_str(delivery["telemetry"].as_str().unwrap())?;
    assert_eq!(proof.slices[0].witnesses[PROFILE].account, "account-alice");
    let mut changed = first.clone();
    changed.players.get_mut(PROFILE).unwrap().movement_steps += 1;
    assert_eq!(
        send(&client, &oracle, "slice", Some(&changed), TOKEN).await?,
        409
    );
    let evidence = receipt["attestation"]["evidence"].as_str().unwrap();
    let response = client
        .get(format!(
            "http://{}/v1/activity/survival/evidence/{evidence}",
            oracle.address()
        ))
        .bearer_auth(TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await?["telemetry"],
        delivery["telemetry"]
    );
    let response = client
        .get(format!(
            "http://{}/v1/activity/survival/evidence/unrelated",
            oracle.address()
        ))
        .bearer_auth(TOKEN)
        .send()
        .await?;
    assert_eq!(response.status(), 404);
    // A complete later batch without native witnesses archives telemetry without minting points.
    for index in 2..8 {
        assert_eq!(
            send(
                &client,
                &oracle,
                "slice",
                Some(&report(start + index * ACTIVITY_SLICE_MS, true)),
                TOKEN
            )
            .await?,
            204
        );
    }
    assert_eq!(fixture.station.receipts.lock().await.len(), 2);
    let receipts = fixture.station.receipts.lock().await;
    let (unwitnessed, _) = receipts
        .values()
        .find(|(value, _)| value["windowStartMs"] == start + 2 * ACTIVITY_SLICE_MS)
        .unwrap();
    assert_eq!(unwitnessed["players"], json!({}));
    drop(receipts);
    fixture.station.enabled.store(false, Ordering::SeqCst);
    assert_eq!(
        send(&client, &oracle, "slice", Some(&first), TOKEN).await?,
        403
    );
    oracle.finish(true).await?;
    fixture.tasks.shutdown().await;
    Ok(())
}
