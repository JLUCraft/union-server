//! Server-side gateway witnesses and an authenticated, event-driven Paper oracle adapter.
use crate::{
    central::Central,
    point_contracts::{
        ACTIVITY_SLICE_MS, ActivityDelivery, ActivityReceipt, ActivitySourceList, ActivityTotals,
        DAY_MS, MAX_EVIDENCE_BYTES, MAX_REPORT_PLAYERS, PointAmount,
    },
    skins::SkinSite,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;
const MAX_SESSIONS: usize = 65_536;
const MAX_REPORT_BYTES: usize = 512 * 1024;
const MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;
const MAX_PACKET_SILENCE_MS: u64 = 60_000;
const BATCH_WINDOW_MS: u64 = 6 * ACTIVITY_SLICE_MS;
const MAX_REPORT_LAG_MS: u64 = DAY_MS;
const MIN_LOOK_SAMPLES: u32 = 8;
const MIN_YAW_VARIANCE_MILLI: u64 = 25_000;
const MIN_PITCH_VARIANCE_MILLI: u64 = 10_000;
const MIN_MOVEMENT_STEPS: u32 = 8;
const MIN_DISTINCT_POSITIONS: u32 = 4;
const MIN_WORLD_INTERACTIONS: u32 = 2;
const MIN_PROGRESS_EVENTS: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityMetrics {
    pub movement_steps: u32,
    pub distinct_positions: u32,
    pub look_samples: u32,
    pub yaw_variance_milli: u64,
    pub pitch_variance_milli: u64,
    pub world_interactions: u32,
    pub progress_events: u32,
}
impl ActivityMetrics {
    fn active(&self) -> bool {
        let look = self.look_samples >= MIN_LOOK_SAMPLES
            && (self.yaw_variance_milli >= MIN_YAW_VARIANCE_MILLI
                || self.pitch_variance_milli >= MIN_PITCH_VARIANCE_MILLI);
        let dimensions = [
            self.movement_steps >= MIN_MOVEMENT_STEPS
                && self.distinct_positions >= MIN_DISTINCT_POSITIONS,
            self.world_interactions >= MIN_WORLD_INTERACTIONS,
            self.progress_events >= MIN_PROGRESS_EVENTS,
        ];
        look && dimensions.into_iter().filter(|active| *active).count() >= 2
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub players: BTreeMap<String, ActivityMetrics>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Witness {
    resource: String,
    uuid: String,
    account: String,
    connected_ms: u64,
    last_packet_ms: u64,
    closed_ms: Option<u64>,
    #[serde(skip)]
    packet_windows: BTreeMap<u64, u64>,
}
#[derive(Default)]
struct WitnessStore {
    next: u64,
    sessions: BTreeMap<u64, Witness>,
}
#[derive(Clone, Default)]
pub struct Witnesses(Arc<Mutex<WitnessStore>>);
pub struct WitnessGuard {
    owner: Witnesses,
    id: u64,
}
impl Witnesses {
    #[cfg(test)]
    pub(crate) fn recorded(&self, resource: &str, account: &str, uuid: &str) -> bool {
        self.0.lock().is_ok_and(|store| {
            store
                .sessions
                .values()
                .any(|w| w.resource == resource && w.account == account && w.uuid == uuid)
        })
    }
    pub(crate) fn begin(&self, resource: &str, uuid: &str, account: &str) -> Result<WitnessGuard> {
        self.begin_at(resource, uuid, account, now_ms()?)
    }
    fn begin_at(
        &self,
        resource: &str,
        uuid: &str,
        account: &str,
        now: u64,
    ) -> Result<WitnessGuard> {
        ensure!(
            !resource.is_empty() && !account.is_empty(),
            "activity identity required"
        );
        ensure!(
            uuid.len() == 32
                && uuid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid activity UUID"
        );
        let mut store = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("witness store unavailable"))?;
        store.sessions.retain(|_, w| {
            w.closed_ms
                .is_none_or(|closed| closed.saturating_add(DAY_MS) >= now)
        });
        ensure!(
            store.sessions.len() < MAX_SESSIONS,
            "witness capacity reached"
        );
        store.next = store
            .next
            .checked_add(1)
            .context("witness sequence exhausted")?;
        let id = store.next;
        store.sessions.insert(
            id,
            Witness {
                resource: resource.into(),
                uuid: uuid.into(),
                account: account.into(),
                connected_ms: now,
                last_packet_ms: now,
                closed_ms: None,
                packet_windows: [(now / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS, now)].into(),
            },
        );
        Ok(WitnessGuard {
            owner: self.clone(),
            id,
        })
    }
    fn covering(
        &self,
        resource: &str,
        uuid: &str,
        start: u64,
        end: u64,
        now: u64,
    ) -> Result<Option<Witness>> {
        let store = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("witness store unavailable"))?;
        Ok(store.sessions.values().find_map(|w| {
            if w.resource != resource
                || w.uuid != uuid
                || w.connected_ms > start
                || w.closed_ms.unwrap_or(now) < end
            {
                return None;
            }
            let last = *w.packet_windows.get(&start)?;
            if last < end.saturating_sub(MAX_PACKET_SILENCE_MS) || last >= end {
                return None;
            }
            let mut proof = w.clone();
            proof.last_packet_ms = last;
            proof.packet_windows.clear();
            Some(proof)
        }))
    }
}
impl WitnessGuard {
    pub fn touch(&self) {
        if let Ok(now) = now_ms() {
            self.touch_at(now);
        }
    }
    fn touch_at(&self, now: u64) {
        if let Ok(mut store) = self.owner.0.lock()
            && let Some(witness) = store.sessions.get_mut(&self.id)
            && now >= witness.last_packet_ms
            && witness.closed_ms.is_none()
        {
            witness.last_packet_ms = now;
            let window = now / ACTIVITY_SLICE_MS * ACTIVITY_SLICE_MS;
            if !witness.packet_windows.contains_key(&window) {
                witness
                    .packet_windows
                    .retain(|start, _| start.saturating_add(DAY_MS) >= now);
            }
            witness.packet_windows.insert(window, now);
        }
    }
}
impl Drop for WitnessGuard {
    fn drop(&mut self) {
        if let Ok(mut store) = self.owner.0.lock()
            && let Some(witness) = store.sessions.get_mut(&self.id)
        {
            witness.closed_ms = Some(now_ms().unwrap_or(witness.last_packet_ms));
        }
    }
}
fn now_ms() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub skin_site: SkinSite,
    pub session_token: PathBuf,
    pub spool: PathBuf,
    pub probes: Vec<Probe>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub source: String,
    pub resource: String,
    pub token: PathBuf,
}
struct Binding {
    resource: String,
    token: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct VerifiedSlice {
    report: ProbeReport,
    witnesses: BTreeMap<String, Witness>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    slices: Vec<VerifiedSlice>,
    delivery: Option<ActivityDelivery>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completed {
    delivery: ActivityDelivery,
    receipt: ActivityReceipt,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceState {
    pending: Pending,
    completed: Vec<Completed>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    slices: Vec<VerifiedSlice>,
}
struct OracleContext {
    central: Central,
    witnesses: Witnesses,
    bindings: BTreeMap<String, Binding>,
    pending: tokio::sync::Mutex<BTreeMap<String, SourceState>>,
    spool: PathBuf,
    _spool_lock: std::fs::File,
}
impl OracleContext {
    fn persist(&self, pending: &BTreeMap<String, SourceState>) -> Result<()> {
        use std::io::Write;
        let bytes = serde_json::to_vec(pending)?;
        ensure!(
            bytes.len() <= MAX_SPOOL_BYTES,
            "activity evidence spool full"
        );
        let next = self.spool.with_extension("next");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&next)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(next, &self.spool)?;
        if let Some(parent) = self.spool.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    async fn source(&self, source: &str) -> Result<u64, StatusCode> {
        let binding = self.bindings.get(source).ok_or(StatusCode::NOT_FOUND)?;
        let bytes = self
            .central
            .request(Method::GET, &["api", "hosted-activity-sources"], None)
            .await?;
        let list: ActivitySourceList =
            serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
        let assigned = list
            .sources
            .into_iter()
            .find(|s| {
                s.config.id.as_str() == source
                    && s.config.enabled
                    && s.config.resource.as_str() == binding.resource
            })
            .ok_or(StatusCode::FORBIDDEN)?;
        u64::try_from(assigned.last_window_end_ms).map_err(|_| StatusCode::BAD_GATEWAY)
    }
    async fn deliver(&self, delivery: &ActivityDelivery) -> Result<ActivityReceipt, StatusCode> {
        let bytes = self
            .central
            .request(
                Method::POST,
                &["api", "points", "activity-deliveries"],
                Some(
                    serde_json::to_value(delivery)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                ),
            )
            .await?;
        let receipt: ActivityReceipt =
            serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
        if receipt.attestation.source.as_str() != delivery.source.as_str()
            || receipt.attestation.window_start_ms != delivery.window_start_ms
            || receipt.attestation.window_end_ms != delivery.window_end_ms
            || serde_json::to_value(&receipt.attestation.players)
                .map_err(|_| StatusCode::BAD_GATEWAY)?
                != serde_json::to_value(&delivery.players).map_err(|_| StatusCode::BAD_GATEWAY)?
        {
            return Err(StatusCode::BAD_GATEWAY);
        }
        Ok(receipt)
    }
    fn delivery(source: &str, slices: &[VerifiedSlice]) -> Result<ActivityDelivery> {
        let mut profiles = std::collections::HashMap::new();
        let mut players: std::collections::HashMap<String, ActivityTotals> =
            std::collections::HashMap::new();
        for slice in slices {
            let mut seen = BTreeSet::new();
            for (uuid, witness) in &slice.witnesses {
                if let Some(previous) = profiles.insert(uuid.clone(), witness.account.clone()) {
                    ensure!(
                        previous == witness.account,
                        "profile account changed within activity window"
                    );
                }
                if !seen.insert(&witness.account) {
                    continue;
                }
                let metrics = slice
                    .report
                    .players
                    .get(uuid)
                    .context("witnessed telemetry missing")?;
                let total = players
                    .entry(witness.account.clone())
                    .or_insert(ActivityTotals {
                        active_slices: 0,
                        afk_slices: 0,
                        bonus_points: PointAmount::try_from("0")?,
                    });
                if metrics.active() {
                    total.active_slices += 1;
                } else {
                    total.afk_slices += 1;
                }
            }
        }
        ensure!(
            profiles.len() <= MAX_REPORT_PLAYERS && players.len() <= MAX_REPORT_PLAYERS,
            "activity batch player limit"
        );
        let telemetry = serde_json::to_string(&Proof {
            slices: slices.to_vec(),
        })?;
        ensure!(
            serde_json::to_vec(&serde_json::json!({"profiles":profiles,"telemetry":telemetry}))?
                .len()
                <= MAX_EVIDENCE_BYTES,
            "activity evidence exceeds artifact limit"
        );
        Ok(serde_json::from_value(serde_json::json!({
            "source": source,
            "windowStartMs": slices.first().context("empty activity batch")?.report.window_start_ms,
            "windowEndMs": slices.last().context("empty activity batch")?.report.window_end_ms,
            "profiles": profiles, "players": players, "telemetry": telemetry,
        }))?)
    }
    async fn flush(
        &self,
        source: &str,
        pending: &mut BTreeMap<String, SourceState>,
    ) -> Result<(), StatusCode> {
        let Some(current) = pending.get_mut(source) else {
            return Ok(());
        };
        if current.pending.slices.is_empty() {
            return Ok(());
        }
        self.source(source).await?;
        let current = pending
            .get_mut(source)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let delivery = match &current.pending.delivery {
            Some(delivery) => delivery.clone(),
            None => {
                let delivery = Self::delivery(source, &current.pending.slices)
                    .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
                current.pending.delivery = Some(delivery.clone());
                delivery
            }
        };
        // Freeze the exact handoff before any request can reach the central ledger.
        self.persist(pending)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let receipt = self.deliver(&delivery).await?;
        let current = pending
            .get_mut(source)
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        current.completed.push(Completed { delivery, receipt });
        current.pending = Pending::default();
        self.persist(pending)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }
    async fn submit(
        &self,
        source: &str,
        headers: &HeaderMap,
        report: ProbeReport,
    ) -> Result<StatusCode, StatusCode> {
        let binding = self.bindings.get(source).ok_or(StatusCode::NOT_FOUND)?;
        crate::bearer::require_bearer(headers, &binding.token)?;
        let now = now_ms().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !report.window_start_ms.is_multiple_of(ACTIVITY_SLICE_MS)
            || report.window_start_ms.checked_add(ACTIVITY_SLICE_MS) != Some(report.window_end_ms)
            || report.window_end_ms > now
            || report.players.len() > MAX_REPORT_PLAYERS
        {
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
        if now.saturating_sub(report.window_end_ms) > MAX_REPORT_LAG_MS {
            return Err(StatusCode::GONE);
        }
        let cursor = self.source(source).await?;
        let mut pending = self.pending.lock().await;
        for current in pending.values_mut() {
            current.completed.retain(|c| {
                u64::try_from(c.delivery.window_end_ms)
                    .is_ok_and(|end| end.saturating_add(DAY_MS) >= now)
            });
        }
        if pending.get(source).is_some_and(|s| {
            s.pending.delivery.is_some()
                || s.pending
                    .slices
                    .last()
                    .is_some_and(|slice| slice.report.window_end_ms <= cursor)
        }) {
            self.flush(source, &mut pending)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        if let Some(current) = pending.get(source) {
            for completed in &current.completed {
                if u64::try_from(completed.delivery.window_start_ms)
                    .is_ok_and(|start| start <= report.window_start_ms)
                    && u64::try_from(completed.delivery.window_end_ms)
                        .is_ok_and(|end| end >= report.window_end_ms)
                {
                    let proof: Proof = serde_json::from_str(&completed.delivery.telemetry)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    if !proof.slices.iter().any(|slice| slice.report == report) {
                        return Err(StatusCode::CONFLICT);
                    }
                    self.deliver(&completed.delivery)
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    self.persist(&pending)
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                    return Ok(StatusCode::NO_CONTENT);
                }
            }
            if let Some(previous) = current
                .pending
                .slices
                .iter()
                .find(|s| s.report.window_start_ms == report.window_start_ms)
            {
                if previous.report != report {
                    return Err(StatusCode::CONFLICT);
                }
                self.persist(&pending)
                    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                return Ok(StatusCode::NO_CONTENT);
            }
            if current
                .pending
                .slices
                .last()
                .is_some_and(|slice| slice.report.window_end_ms > report.window_start_ms)
            {
                return Err(StatusCode::CONFLICT);
            }
        }
        if report.window_start_ms < cursor {
            return Err(StatusCode::CONFLICT);
        }
        let mut witnesses = BTreeMap::new();
        for uuid in report.players.keys() {
            if let Some(witness) = self
                .witnesses
                .covering(
                    &binding.resource,
                    uuid,
                    report.window_start_ms,
                    report.window_end_ms,
                    now,
                )
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            {
                witnesses.insert(uuid.clone(), witness);
            }
        }
        let slice = VerifiedSlice { report, witnesses };
        let current = pending.entry(source.into()).or_default();
        let mut candidate = current.pending.slices.clone();
        candidate.push(slice.clone());
        if !current.pending.slices.is_empty()
            && (current
                .pending
                .slices
                .last()
                .is_some_and(|s| s.report.window_end_ms != slice.report.window_start_ms)
                || Self::delivery(source, &candidate).is_err())
        {
            self.flush(source, &mut pending)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        let current = pending.entry(source.into()).or_default();
        current.pending.slices.push(slice);
        let first = current
            .pending
            .slices
            .first()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
            .report
            .window_start_ms;
        let last = current
            .pending
            .slices
            .last()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
            .report
            .window_end_ms;
        if last.saturating_sub(first) >= BATCH_WINDOW_MS {
            self.flush(source, &mut pending)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        }
        self.persist(&pending)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(StatusCode::NO_CONTENT)
    }
}
async fn report(
    State(context): State<Arc<OracleContext>>,
    Path(source): Path<String>,
    headers: HeaderMap,
    Json(report): Json<ProbeReport>,
) -> Result<StatusCode, StatusCode> {
    context.submit(&source, &headers, report).await
}
async fn flush(
    State(context): State<Arc<OracleContext>>,
    Path(source): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let binding = context.bindings.get(&source).ok_or(StatusCode::NOT_FOUND)?;
    crate::bearer::require_bearer(&headers, &binding.token)?;
    context.source(&source).await?;
    let mut pending = context.pending.lock().await;
    context.flush(&source, &mut pending).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn evidence(
    State(context): State<Arc<OracleContext>>,
    Path((source, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let binding = context.bindings.get(&source).ok_or(StatusCode::NOT_FOUND)?;
    crate::bearer::require_bearer(&headers, &binding.token)?;
    context.source(&source).await?;
    let pending = context.pending.lock().await;
    if !pending.get(&source).is_some_and(|s| {
        s.completed
            .iter()
            .any(|c| c.receipt.attestation.evidence.as_str() == id)
    }) {
        return Err(StatusCode::NOT_FOUND);
    }
    drop(pending);
    let bytes = context
        .central
        .request(Method::GET, &["api", "artifacts", &id, "content"], None)
        .await?;
    serde_json::from_slice(&bytes)
        .map(Json)
        .map_err(|_| StatusCode::BAD_GATEWAY)
}
pub struct Oracle {
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    completion: tokio::sync::watch::Receiver<()>,
    address: SocketAddr,
}
impl Oracle {
    pub async fn start(config: Config, witnesses: Witnesses) -> Result<Self> {
        ensure!(
            config.bind.ip().is_loopback(),
            "activity adapter must bind loopback"
        );
        ensure!(
            !config.probes.is_empty() && config.probes.len() <= MAX_REPORT_PLAYERS,
            "invalid activity probe count"
        );
        let central = Central::new(config.skin_site, config.session_token)?;
        let mut bindings = BTreeMap::new();
        for probe in config.probes {
            ensure!(
                !probe.source.is_empty()
                    && probe.source.len() <= 128
                    && !probe.resource.is_empty()
                    && probe.resource.len() <= 128,
                "invalid activity assignment"
            );
            crate::bootstrap::require_private(&probe.token, "activity probe token")?;
            let token = crate::central::credential(&probe.token, 256)?.into_bytes();
            ensure!(
                bindings
                    .insert(
                        probe.source,
                        Binding {
                            resource: probe.resource,
                            token
                        }
                    )
                    .is_none(),
                "duplicate activity source"
            );
        }
        let parent = config
            .spool
            .parent()
            .context("activity spool directory missing")?;
        ensure!(parent.is_dir(), "activity spool directory missing");
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(config.spool.with_extension("lock"))?;
        lock.try_lock().context("activity spool already open")?;
        let pending: BTreeMap<String, SourceState> = if config.spool.exists() {
            crate::bootstrap::require_private(&config.spool, "activity evidence spool")?;
            ensure!(
                std::fs::metadata(&config.spool)?.len() <= MAX_SPOOL_BYTES as u64,
                "activity evidence spool too large"
            );
            serde_json::from_slice(&std::fs::read(&config.spool)?)?
        } else {
            BTreeMap::new()
        };
        ensure!(
            pending.keys().all(|source| bindings.contains_key(source)),
            "activity spool has unconfigured sources"
        );
        let context = Arc::new(OracleContext {
            central,
            witnesses,
            bindings,
            pending: tokio::sync::Mutex::new(pending),
            spool: config.spool,
            _spool_lock: lock,
        });
        let listener = tokio::net::TcpListener::bind(config.bind).await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/v1/activity/{source}/slice", post(report))
            .route("/v1/activity/{source}/flush", post(flush))
            .route("/v1/activity/{source}/evidence/{id}", get(evidence))
            .layer(DefaultBodyLimit::max(MAX_REPORT_BYTES))
            .with_state(context.clone());
        let (stop, stopping) = oneshot::channel();
        let (completed, completion) = tokio::sync::watch::channel(());
        let task = tokio::spawn(async move {
            let _completed = completed;
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopping.await;
                })
                .await?;
            let mut pending = context.pending.lock().await;
            let mut failure = None;
            for source in pending.keys().cloned().collect::<Vec<_>>() {
                if let Err(error) = context.flush(&source, &mut pending).await {
                    failure = Some(anyhow::anyhow!(
                        "central activity delivery rejected: {error}"
                    ));
                }
            }
            context.persist(&pending)?;
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(())
        });
        Ok(Self {
            stop: Some(stop),
            task: Some(task),
            completion,
            address,
        })
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub async fn closed(&self) {
        let mut completion = self.completion.clone();
        let _ = completion.changed().await;
    }
    pub async fn stop(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Oracle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
#[cfg(test)]
#[path = "activity_tests.rs"]
mod tests;
