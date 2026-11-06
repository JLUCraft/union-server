//! Metrics, console, persistent jobs, audit, and transactional archives for operations.
use crate::ops::{Fleet, Managed};
use anyhow::{Context, Result, ensure};
use minecraftd::{
    archive::{
        manager::{ArchiveConfig, ArchiveManager},
        metadata::{ArchiveMetadata, ArchiveScope},
        strategy::FullArchiveStrategy,
    },
    core::state::InstanceState,
    minecraft::ping::ping_java_server,
};
use node::protocol::{
    OpsAuditRecord, OpsBackup, OpsCapabilities, OpsError, OpsErrorCode, OpsJob, OpsJobKind,
    OpsJobState, OpsMetrics, OpsOp, OpsRequest, OpsResponse, digest,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use sysinfo::{Disks, Pid, ProcessesToUpdate, System};
use tokio::{sync::Mutex, task::JoinSet, time::timeout};

const MAX_COMMAND_BYTES: usize = 1024;
const COMMAND_OUTPUT_LINES: usize = 100;
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 128;
const MAX_JOBS: usize = 256;
const MAX_JOB_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_AUDIT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AUDIT_RECORDS: usize = 1024;
const OP_TIMEOUT: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_OUTPUT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct Fault {
    code: OpsErrorCode,
    message: String,
}
impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Fault {}

pub(crate) fn fault(code: OpsErrorCode, message: impl Into<String>) -> anyhow::Error {
    Fault {
        code,
        message: message.into(),
    }
    .into()
}

pub(crate) fn error_response(error: &anyhow::Error) -> OpsError {
    error.downcast_ref::<Fault>().map_or_else(
        || OpsError {
            code: OpsErrorCode::Failed,
            message: error.to_string(),
        },
        |error| OpsError {
            code: error.code,
            message: error.message.clone(),
        },
    )
}

fn invalid(message: impl Into<String>) -> anyhow::Error {
    fault(OpsErrorCode::InvalidRequest, message)
}

fn now_ms() -> Result<u64> {
    Ok(authority::journal::now_ms()?)
}

fn request_digest(request: &OpsRequest) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&OpsRequest {
        op: request.op.clone(),
        delegation: None,
    })?))
}

fn delegation_metadata(request: &OpsRequest) -> (Option<String>, Option<String>) {
    request
        .delegation
        .as_ref()
        .map_or((None, None), |delegation| {
            let claims = &delegation.envelope.claims;
            (Some(claims.aud.gateway.clone()), Some(claims.nonce.clone()))
        })
}

pub(crate) fn is_extended(op: &OpsOp) -> bool {
    matches!(
        op,
        OpsOp::Capabilities {}
            | OpsOp::Metrics { .. }
            | OpsOp::Command { .. }
            | OpsOp::ListJobs { .. }
            | OpsOp::GetJob { .. }
            | OpsOp::ListAudit { .. }
            | OpsOp::ListBackups { .. }
            | OpsOp::CreateBackup { .. }
            | OpsOp::VerifyBackup { .. }
            | OpsOp::RestoreBackup { .. }
            | OpsOp::DeleteBackup { .. }
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredJobs {
    version: u32,
    jobs: Vec<OpsJob>,
}

struct JobStore {
    path: PathBuf,
    jobs: Mutex<BTreeMap<String, OpsJob>>,
}
impl JobStore {
    fn new(path: PathBuf) -> Result<Self> {
        let mut jobs = BTreeMap::new();
        let mut recovered = false;
        if path.exists() {
            ensure!(
                std::fs::metadata(&path)?.len() <= MAX_JOB_FILE_BYTES,
                "operations job file too large"
            );
            let stored: StoredJobs = serde_json::from_slice(&std::fs::read(&path)?)?;
            ensure!(stored.version == 1, "unsupported operations job version");
            for mut job in stored.jobs {
                if matches!(job.state, OpsJobState::Queued | OpsJobState::Running) {
                    job.state = OpsJobState::Failed;
                    job.updated_ms = now_ms()?;
                    job.error = Some(OpsError {
                        code: OpsErrorCode::Failed,
                        message: "server restarted before the job completed".into(),
                    });
                    recovered = true;
                }
                jobs.insert(job.id.clone(), job);
            }
        }
        if recovered {
            persist_jobs(&path, &jobs)?;
        }
        Ok(Self {
            path,
            jobs: Mutex::new(jobs),
        })
    }

    fn persist_sync(&self, jobs: &BTreeMap<String, OpsJob>) -> Result<()> {
        persist_jobs(&self.path, jobs)
    }

    async fn idempotent(
        &self,
        actor: &str,
        key: &str,
        request_digest: &str,
    ) -> Result<Option<OpsJob>> {
        let jobs = self.jobs.lock().await;
        let existing = jobs
            .values()
            .find(|job| job.actor == actor && job.idempotency_key.as_deref() == Some(key));
        match existing {
            Some(job) if job.request_digest != request_digest => Err(fault(
                OpsErrorCode::Conflict,
                "idempotency key was already used for another request",
            )),
            Some(job) => Ok(Some(job.clone())),
            None => Ok(None),
        }
    }

    async fn create(&self, new: NewJob<'_>) -> Result<OpsJob> {
        let mut jobs = self.jobs.lock().await;
        let mut next = jobs.clone();
        let now = now_ms()?;
        let id = node::ServiceId::new().to_string();
        let job = OpsJob {
            id: id.clone(),
            kind: new.kind,
            state: OpsJobState::Queued,
            actor: new.actor.into(),
            instance: new.instance.into(),
            backup: new.backup,
            backup_label: new.backup_label,
            result_backup: None,
            safety_backup: None,
            verified: None,
            created_ms: now,
            updated_ms: now,
            error: None,
            idempotency_key: Some(new.key),
            request_digest: new.request_digest,
        };
        next.insert(id, job.clone());
        while next.len() > MAX_JOBS {
            let oldest = next
                .values()
                .filter(|job| matches!(job.state, OpsJobState::Succeeded | OpsJobState::Failed))
                .min_by_key(|job| job.updated_ms)
                .map(|job| job.id.clone());
            let Some(oldest) = oldest else {
                return Err(fault(OpsErrorCode::Busy, "too many active operations jobs"));
            };
            next.remove(&oldest);
        }
        self.persist_sync(&next)?;
        *jobs = next;
        Ok(job)
    }

    async fn start(&self, id: &str) -> Result<()> {
        let mut jobs = self.jobs.lock().await;
        let mut next = jobs.clone();
        let job = next.get_mut(id).context("operations job disappeared")?;
        job.state = OpsJobState::Running;
        job.updated_ms = now_ms()?;
        self.persist_sync(&next)?;
        *jobs = next;
        Ok(())
    }

    async fn complete(&self, id: &str, result: Result<JobOutcome>) -> Result<OpsJob> {
        let mut jobs = self.jobs.lock().await;
        let mut next = jobs.clone();
        let job = next.get_mut(id).context("operations job disappeared")?;
        job.updated_ms = now_ms()?;
        match result {
            Ok(outcome) => {
                job.state = OpsJobState::Succeeded;
                job.result_backup = outcome.result_backup;
                job.safety_backup = outcome.safety_backup;
                job.verified = outcome.verified;
                job.error = None;
            }
            Err(error) => {
                job.state = OpsJobState::Failed;
                job.error = Some(error_response(&error));
            }
        }
        let job = job.clone();
        self.persist_sync(&next)?;
        *jobs = next;
        Ok(job)
    }

    async fn get(&self, id: &str) -> Result<OpsJob> {
        self.jobs
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| fault(OpsErrorCode::NotFound, "unknown operations job"))
    }

    async fn page(&self, offset: u32, limit: Option<u32>) -> Result<(Vec<OpsJob>, Option<u32>)> {
        let jobs = self.jobs.lock().await;
        let mut values = jobs.values().cloned().collect::<Vec<_>>();
        values.sort_by(|a, b| {
            b.created_ms
                .cmp(&a.created_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        page(values, offset, limit)
    }
}

fn persist_jobs(path: &Path, jobs: &BTreeMap<String, OpsJob>) -> Result<()> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(&StoredJobs {
        version: 1,
        jobs: jobs.values().cloned().collect(),
    })?;
    ensure!(
        bytes.len() as u64 <= MAX_JOB_FILE_BYTES,
        "operations job file too large"
    );
    let temporary = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(temporary, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

struct NewJob<'a> {
    kind: OpsJobKind,
    actor: &'a str,
    instance: &'a str,
    backup: Option<String>,
    backup_label: Option<String>,
    key: String,
    request_digest: String,
}

struct AuditStore {
    path: PathBuf,
    records: Mutex<VecDeque<OpsAuditRecord>>,
}
impl AuditStore {
    fn new(path: PathBuf) -> Result<Self> {
        let mut records = VecDeque::new();
        if path.exists() {
            ensure!(
                std::fs::metadata(&path)?.len() <= MAX_AUDIT_FILE_BYTES,
                "operations audit file exceeds the MVP retention limit"
            );
            for line in std::fs::read_to_string(&path)?
                .lines()
                .filter(|line| !line.is_empty())
            {
                records.push_back(serde_json::from_str(line)?);
            }
            while records.len() > MAX_AUDIT_RECORDS {
                records.pop_front();
            }
        }
        Ok(Self {
            path,
            records: Mutex::new(records),
        })
    }

    async fn record(&self, record: OpsAuditRecord) -> Result<()> {
        if let Some(parent) = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        let mut records = self.records.lock().await;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        records.push_back(record);
        while records.len() > MAX_AUDIT_RECORDS {
            records.pop_front();
        }
        Ok(())
    }

    async fn page(
        &self,
        offset: u32,
        limit: Option<u32>,
    ) -> Result<(Vec<OpsAuditRecord>, Option<u32>)> {
        let values = self
            .records
            .lock()
            .await
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        page(values, offset, limit)
    }
}

pub(crate) struct Extended {
    jobs: JobStore,
    audit: AuditStore,
    archives: ArchiveManager,
    tasks: Mutex<JoinSet<()>>,
    system: Mutex<System>,
}
impl Extended {
    pub(crate) fn new(state: PathBuf, audit: PathBuf, archives: ArchiveConfig) -> Result<Self> {
        Ok(Self {
            jobs: JobStore::new(state)?,
            audit: AuditStore::new(audit)?,
            archives: ArchiveManager::new(archives),
            tasks: Mutex::new(JoinSet::new()),
            system: Mutex::new(System::new()),
        })
    }

    pub(crate) async fn shutdown(&self) -> Result<()> {
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.join_next().await {
            result.context("operations job task failed")?;
        }
        Ok(())
    }
}

fn page<T>(values: Vec<T>, offset: u32, limit: Option<u32>) -> Result<(Vec<T>, Option<u32>)> {
    let limit = limit.unwrap_or(node::protocol::OPS_PAGE_LIMIT);
    if limit == 0 || limit > node::protocol::OPS_PAGE_LIMIT {
        return Err(invalid("invalid page limit"));
    }
    let start = offset as usize;
    let end = start.saturating_add(limit as usize);
    let next = (end < values.len()).then_some(end as u32);
    let values = values
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .collect();
    Ok((values, next))
}

async fn record_audit_or_log(
    store: &AuditStore,
    action: &str,
    target: Option<&str>,
    record: Result<OpsAuditRecord>,
) {
    let result = match record {
        Ok(record) => store.record(record).await,
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        tracing::error!(action, target, %error, "operations audit record lost");
    }
}

pub(crate) async fn audit_legacy(
    fleet: &Fleet,
    request: &OpsRequest,
    actor: &str,
    response: &OpsResponse,
) {
    if !matches!(
        request.op,
        OpsOp::Start { .. }
            | OpsOp::StartLeague { .. }
            | OpsOp::StopLeague { .. }
            | OpsOp::Stop { .. }
            | OpsOp::Restart { .. }
            | OpsOp::Kill { .. }
    ) {
        return;
    }
    let action = match &request.op {
        OpsOp::Start { .. } => "start",
        OpsOp::StartLeague { .. } => "start_league",
        OpsOp::StopLeague { .. } => "stop_league",
        OpsOp::Stop { .. } => "stop",
        OpsOp::Restart { .. } => "restart",
        OpsOp::Kill { .. } => "kill",
        _ => return,
    };
    let target = match &request.op {
        OpsOp::Start { instance }
        | OpsOp::StartLeague { instance, .. }
        | OpsOp::StopLeague { instance, .. }
        | OpsOp::Stop { instance }
        | OpsOp::Restart { instance }
        | OpsOp::Kill { instance } => Some(instance.clone()),
        _ => None,
    };
    let (relay, nonce) = delegation_metadata(request);
    let record = (|| {
        Ok(OpsAuditRecord {
            relay,
            nonce,
            timestamp_ms: now_ms()?,
            actor: actor.into(),
            action: action.into(),
            target: target.clone(),
            request_digest: request_digest(request)?,
            success: response.ok,
            error_code: response.error.as_ref().map(|error| error.code),
            job: None,
            command: None,
        })
    })();
    record_audit_or_log(&fleet.extended.audit, action, target.as_deref(), record).await;
}

pub(crate) async fn execute(
    fleet: &Arc<Fleet>,
    request: OpsRequest,
    actor: &str,
) -> Result<OpsResponse> {
    let (relay, nonce) = delegation_metadata(&request);
    let mut response = OpsResponse {
        ok: true,
        ..Default::default()
    };
    match &request.op {
        OpsOp::Capabilities {} => {
            response.capabilities = Some(OpsCapabilities {
                persistent_jobs: true,
                metrics: true,
                console: true,
                backups: true,
                audit: true,
                max_command_bytes: MAX_COMMAND_BYTES,
                max_page_limit: node::protocol::OPS_PAGE_LIMIT,
            });
        }
        OpsOp::Metrics { instance } => {
            response.metrics = metrics(fleet, instance.as_deref()).await?;
        }
        OpsOp::Command { instance, command } => {
            let result = execute_command(fleet, instance, command).await;
            let success = result.is_ok();
            let error_code = result
                .as_ref()
                .err()
                .map(|error| error_response(error).code);
            let record = (|| {
                Ok(OpsAuditRecord {
                    relay,
                    nonce,
                    timestamp_ms: now_ms()?,
                    actor: actor.into(),
                    action: "command".into(),
                    target: Some(instance.clone()),
                    request_digest: request_digest(&request)?,
                    success,
                    error_code,
                    job: None,
                    command: Some(command.clone()),
                })
            })();
            record_audit_or_log(&fleet.extended.audit, "command", Some(instance), record).await;
            response.logs = Some(result?);
        }
        OpsOp::ListJobs { offset, limit } => {
            let (jobs, next_offset) = fleet.extended.jobs.page(*offset, *limit).await?;
            response.jobs = jobs;
            response.next_offset = next_offset;
        }
        OpsOp::GetJob { job } => {
            response.job = Some(fleet.extended.jobs.get(job).await?);
        }
        OpsOp::ListAudit { offset, limit } => {
            let (audit, next_offset) = fleet.extended.audit.page(*offset, *limit).await?;
            response.audit = audit;
            response.next_offset = next_offset;
        }
        OpsOp::ListBackups {
            instance,
            offset,
            limit,
        } => {
            managed(fleet, instance)?;
            let mut backups = fleet
                .extended
                .archives
                .list(instance)
                .await?
                .iter()
                .map(backup_from_metadata)
                .collect::<Vec<_>>();
            backups.sort_by(|a, b| {
                b.created_at_ms
                    .cmp(&a.created_at_ms)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let (backups, next_offset) = page(backups, *offset, *limit)?;
            response.backups = backups;
            response.next_offset = next_offset;
        }
        OpsOp::CreateBackup { .. } | OpsOp::VerifyBackup { .. } | OpsOp::RestoreBackup { .. } => {
            response.job = Some(submit(fleet, &request, actor).await?);
        }
        OpsOp::DeleteBackup { instance, backup } => {
            let result = async {
                let managed = managed(fleet, instance)?;
                let _operation = managed.operation.clone().try_lock_owned().map_err(|_| {
                    fault(OpsErrorCode::Busy, "instance operation already in progress")
                })?;
                find_backup(fleet, instance, backup).await?;
                fleet.extended.archives.delete(backup).await?;
                Ok(())
            }
            .await;
            let success = result.is_ok();
            let error_code = result
                .as_ref()
                .err()
                .map(|error| error_response(error).code);
            let record = (|| {
                Ok(OpsAuditRecord {
                    relay,
                    nonce,
                    timestamp_ms: now_ms()?,
                    actor: actor.into(),
                    action: "delete_backup".into(),
                    target: Some(instance.clone()),
                    request_digest: request_digest(&request)?,
                    success,
                    error_code,
                    job: None,
                    command: None,
                })
            })();
            record_audit_or_log(
                &fleet.extended.audit,
                "delete_backup",
                Some(instance),
                record,
            )
            .await;
            result?;
        }
        _ => return Err(invalid("legacy operation dispatched through extended path")),
    }
    Ok(response)
}

fn managed<'a>(fleet: &'a Fleet, instance: &str) -> Result<&'a Arc<Managed>> {
    fleet
        .instances
        .get(instance)
        .ok_or_else(|| fault(OpsErrorCode::NotFound, "unknown instance"))
}

async fn execute_command(fleet: &Fleet, instance: &str, command: &str) -> Result<String> {
    if command.is_empty() || command.len() > MAX_COMMAND_BYTES {
        return Err(invalid("invalid command length"));
    }
    if command
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(invalid("command must be one line"));
    }
    let managed = managed(fleet, instance)?;
    if managed.instance.state() != InstanceState::Running {
        return Err(fault(OpsErrorCode::InvalidState, "instance is not running"));
    }
    let _operation = managed
        .operation
        .clone()
        .try_lock_owned()
        .map_err(|_| fault(OpsErrorCode::Busy, "instance operation already in progress"))?;
    let (before_start, before) = managed
        .instance
        .recent_output_with_offset(COMMAND_OUTPUT_LINES)
        .await?;
    let before_end = before_start + before.len() as u64;
    managed.instance.send_command(command.into()).await?;
    timeout(COMMAND_OUTPUT_TIMEOUT, async {
        loop {
            let (after_start, after) = managed
                .instance
                .recent_output_with_offset(COMMAND_OUTPUT_LINES)
                .await?;
            if let Some(output) = command_output_since(before_end, after_start, &after) {
                return Ok(output);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| Ok(String::new()))
}

fn command_output_since(before_end: u64, after_start: u64, after: &[String]) -> Option<String> {
    let skip = before_end
        .saturating_sub(after_start)
        .min(after.len() as u64) as usize;
    if skip == after.len() {
        return None;
    }
    let output = after[skip..].join("\n");
    if after_start > before_end {
        let dropped = after_start - before_end;
        Some(format!(
            "[output lines dropped before this window: {dropped}]\n{output}"
        ))
    } else {
        Some(output)
    }
}

struct MetricSeed {
    target: String,
    process_id: Option<u32>,
    play_time_seconds: Option<u64>,
    responsive: Option<bool>,
    directory: PathBuf,
}

async fn metrics(fleet: &Fleet, instance: Option<&str>) -> Result<Vec<OpsMetrics>> {
    let mut seeds = Vec::new();
    if let Some(instance) = instance {
        seeds.push(instance_metric(managed(fleet, instance)?).await?);
    } else {
        seeds.push(MetricSeed {
            target: "host".into(),
            process_id: Some(std::process::id()),
            play_time_seconds: None,
            responsive: None,
            directory: std::env::current_dir()?,
        });
        for managed in fleet.instances.values() {
            seeds.push(instance_metric(managed).await?);
        }
    }
    let timestamp_ms = now_ms()?;
    let mut system = fleet.extended.system.lock().await;
    system.refresh_processes(ProcessesToUpdate::All, true);
    let disks = Disks::new_with_refreshed_list();
    Ok(seeds
        .into_iter()
        .map(|seed| {
            let process = seed
                .process_id
                .and_then(|pid| system.process(Pid::from_u32(pid)));
            OpsMetrics {
                target: seed.target,
                timestamp_ms,
                process_id: seed.process_id.filter(|_| process.is_some()),
                cpu_milli_percent: process.map(|process| (process.cpu_usage() * 1000.0) as u32),
                memory_bytes: process.map(|process| process.memory()),
                play_time_seconds: seed.play_time_seconds,
                responsive: seed.responsive,
                disk_available_bytes: disk_available(&disks, &seed.directory),
            }
        })
        .collect())
}

async fn instance_metric(managed: &Managed) -> Result<MetricSeed> {
    let running = managed.instance.state() == InstanceState::Running;
    let responsive = if running {
        Some(
            ping_java_server(&managed.config.backend.to_string(), PING_TIMEOUT)
                .await
                .is_ok(),
        )
    } else {
        Some(false)
    };
    Ok(MetricSeed {
        target: managed.config.id.clone(),
        process_id: managed.instance.process_id().await,
        play_time_seconds: Some(managed.instance.play_time_secs().await),
        responsive,
        directory: managed.config.directory.clone(),
    })
}

fn disk_available(disks: &Disks, path: &Path) -> Option<u64> {
    disks
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(|disk| disk.available_space())
}

fn backup_from_metadata(metadata: &ArchiveMetadata) -> OpsBackup {
    OpsBackup {
        id: metadata.id.clone(),
        instance: metadata.instance_id.clone(),
        label: metadata.label.clone(),
        created_at_ms: metadata.created_at.timestamp_millis(),
        scope: match &metadata.scope {
            ArchiveScope::Full => "full".into(),
            ArchiveScope::Worlds => "worlds".into(),
            ArchiveScope::Custom { .. } => "custom".into(),
        },
        sha256: metadata.sha256.clone(),
        original_size: metadata.original_size,
        compressed_size: metadata.compressed_size,
    }
}

async fn find_backup(fleet: &Fleet, instance: &str, backup: &str) -> Result<ArchiveMetadata> {
    fleet
        .extended
        .archives
        .list(instance)
        .await?
        .into_iter()
        .find(|metadata| metadata.id == backup)
        .ok_or_else(|| fault(OpsErrorCode::NotFound, "unknown backup for instance"))
}

#[derive(Default)]
struct JobOutcome {
    result_backup: Option<OpsBackup>,
    safety_backup: Option<OpsBackup>,
    verified: Option<bool>,
}

async fn submit(fleet: &Arc<Fleet>, request: &OpsRequest, actor: &str) -> Result<OpsJob> {
    let (kind, instance, backup, backup_label, key) = match &request.op {
        OpsOp::CreateBackup {
            instance,
            label,
            idempotency_key,
        } => {
            if label.trim().is_empty()
                || label.len() > MAX_LABEL_BYTES
                || label.chars().any(char::is_control)
            {
                return Err(invalid("invalid backup label"));
            }
            (
                OpsJobKind::CreateBackup,
                instance,
                None,
                Some(label.trim().to_owned()),
                idempotency_key,
            )
        }
        OpsOp::VerifyBackup {
            instance,
            backup,
            idempotency_key,
        } => (
            OpsJobKind::VerifyBackup,
            instance,
            Some(backup),
            None,
            idempotency_key,
        ),
        OpsOp::RestoreBackup {
            instance,
            backup,
            idempotency_key,
        } => (
            OpsJobKind::RestoreBackup,
            instance,
            Some(backup),
            None,
            idempotency_key,
        ),
        _ => return Err(invalid("operation is not a job")),
    };
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_BYTES || key.chars().any(char::is_control) {
        return Err(invalid("invalid idempotency key"));
    }
    let digest = request_digest(request)?;
    if let Some(job) = fleet.extended.jobs.idempotent(actor, key, &digest).await? {
        return Ok(job);
    }
    let managed = managed(fleet, instance)?.clone();
    if let Some(backup) = backup {
        find_backup(fleet, instance, backup).await?;
    }
    let operation = managed
        .operation
        .clone()
        .try_lock_owned()
        .map_err(|_| fault(OpsErrorCode::Busy, "instance operation already in progress"))?;
    let job = fleet
        .extended
        .jobs
        .create(NewJob {
            kind,
            actor,
            instance,
            backup: backup.map(String::from),
            backup_label,
            key: key.clone(),
            request_digest: digest,
        })
        .await?;
    let (relay, nonce) = delegation_metadata(request);
    let running = fleet.clone();
    let running_job = job.clone();
    fleet.extended.tasks.lock().await.spawn(async move {
        let _operation = operation;
        let result = async {
            running.extended.jobs.start(&running_job.id).await?;
            run_job(&running, &running_job, managed).await
        }
        .await;
        let completed = running.extended.jobs.complete(&running_job.id, result).await;
        match completed {
            Ok(job) => {
                let record = now_ms().map(|timestamp_ms| OpsAuditRecord {
                    relay,
                    nonce,
                    timestamp_ms,
                    actor: job.actor.clone(),
                    action: match job.kind {
                        OpsJobKind::CreateBackup => "create_backup",
                        OpsJobKind::VerifyBackup => "verify_backup",
                        OpsJobKind::RestoreBackup => "restore_backup",
                    }.into(),
                    target: Some(job.instance.clone()),
                    request_digest: job.request_digest.clone(),
                    success: job.state == OpsJobState::Succeeded,
                    error_code: job.error.as_ref().map(|error| error.code),
                    job: Some(job.id.clone()),
                    command: None,
                });
                let action = match job.kind {
                    OpsJobKind::CreateBackup => "create_backup",
                    OpsJobKind::VerifyBackup => "verify_backup",
                    OpsJobKind::RestoreBackup => "restore_backup",
                };
                record_audit_or_log(
                    &running.extended.audit,
                    action,
                    Some(&job.instance),
                    record,
                ).await;
            }
            Err(error) => tracing::error!(%error, job = %running_job.id, "operations job completion persistence failed"),
        }
    });
    Ok(job)
}

async fn run_job(fleet: &Arc<Fleet>, job: &OpsJob, managed: Arc<Managed>) -> Result<JobOutcome> {
    match job.kind {
        OpsJobKind::CreateBackup => {
            let was_running = stop_for_archive(&managed).await?;
            let result = create_archive(fleet, &managed, job).await;
            let restart = if was_running {
                start_instance(&managed).await
            } else {
                Ok(())
            };
            let metadata = match (result, restart) {
                (Ok(metadata), Ok(())) => metadata,
                (Err(error), Ok(())) => return Err(error),
                (Ok(_), Err(error)) => return Err(error),
                (Err(error), Err(restart)) => {
                    return Err(fault(
                        OpsErrorCode::Failed,
                        format!("{error}; additionally failed to restart instance: {restart}"),
                    ));
                }
            };
            Ok(JobOutcome {
                result_backup: Some(backup_from_metadata(&metadata)),
                ..Default::default()
            })
        }
        OpsJobKind::VerifyBackup => {
            let backup = job.backup.as_ref().context("backup target missing")?;
            find_backup(fleet, &job.instance, backup).await?;
            let verified = fleet.extended.archives.verify(backup).await?;
            ensure!(verified, "backup checksum does not match");
            Ok(JobOutcome {
                verified: Some(true),
                ..Default::default()
            })
        }
        OpsJobKind::RestoreBackup => restore(fleet, job, managed).await,
    }
}

async fn stop_for_archive(managed: &Managed) -> Result<bool> {
    let was_running = match managed.instance.state() {
        InstanceState::Running => true,
        InstanceState::Stopped => false,
        _ => {
            return Err(fault(
                OpsErrorCode::InvalidState,
                "instance is not in a stable state",
            ));
        }
    };
    if was_running {
        stop_instance(managed).await?;
    }
    Ok(was_running)
}

async fn create_archive(fleet: &Fleet, managed: &Managed, job: &OpsJob) -> Result<ArchiveMetadata> {
    let label = match &job.kind {
        OpsJobKind::CreateBackup => job
            .backup_label
            .as_deref()
            .context("backup label missing")?,
        OpsJobKind::RestoreBackup => "before restore",
        OpsJobKind::VerifyBackup => return Err(invalid("verify cannot create an archive")),
    };
    let metadata = fleet
        .extended
        .archives
        .create(
            &managed.config.id,
            &managed.config.directory,
            label,
            InstanceState::Stopped,
            None,
            &FullArchiveStrategy::new(),
        )
        .await?;
    ensure!(
        fleet.extended.archives.verify(&metadata.id).await?,
        "created backup failed verification"
    );
    Ok(metadata)
}

async fn restore(fleet: &Arc<Fleet>, job: &OpsJob, managed: Arc<Managed>) -> Result<JobOutcome> {
    let backup = job.backup.as_ref().context("backup target missing")?;
    let metadata = find_backup(fleet, &job.instance, backup).await?;
    let was_running = stop_for_archive(&managed).await?;
    let safety = match create_archive(fleet, &managed, job).await {
        Ok(metadata) => metadata,
        Err(error) => {
            if was_running {
                start_instance(&managed).await?;
            }
            return Err(error);
        }
    };
    let parent = managed
        .config
        .directory
        .parent()
        .context("instance directory has no parent")?;
    let staging = parent.join(format!(".{}-restore-{}", managed.config.id, job.id));
    let rollback = parent.join(format!(".{}-rollback-{}", managed.config.id, job.id));
    ensure!(
        !staging.exists() && !rollback.exists(),
        "restore staging path already exists"
    );
    let mut swapped = false;
    let result = async {
        fleet.extended.archives.restore(backup, &staging).await?;
        tokio::fs::rename(&managed.config.directory, &rollback).await?;
        swapped = true;
        if let Err(error) = tokio::fs::rename(&staging, &managed.config.directory).await {
            tokio::fs::rename(&rollback, &managed.config.directory).await?;
            swapped = false;
            return Err(error.into());
        }
        if was_running {
            start_instance(&managed).await?;
        }
        Ok(())
    }
    .await;
    if result.is_ok() {
        if rollback.exists()
            && let Err(error) = tokio::fs::remove_dir_all(&rollback).await
        {
            tracing::warn!(%error, path = %rollback.display(), "restore rollback cleanup failed");
        }
        return Ok(JobOutcome {
            result_backup: Some(backup_from_metadata(&metadata)),
            safety_backup: Some(backup_from_metadata(&safety)),
            verified: None,
        });
    }
    let operation_error = result.err().context("restore failed")?;
    let mut rollback_errors = Vec::new();
    if managed.instance.state() == InstanceState::Running
        && let Err(error) = managed.instance.kill().await
    {
        rollback_errors.push(format!("stop restored instance: {error}"));
    }
    if swapped && managed.config.directory.exists() {
        let failed = parent.join(format!(".{}-failed-{}", managed.config.id, job.id));
        if let Err(error) = tokio::fs::rename(&managed.config.directory, &failed).await {
            rollback_errors.push(format!("preserve failed restore: {error}"));
        }
    }
    if rollback.exists()
        && !managed.config.directory.exists()
        && let Err(error) = tokio::fs::rename(&rollback, &managed.config.directory).await
    {
        rollback_errors.push(format!("restore original directory: {error}"));
    }
    if staging.exists()
        && let Err(error) = tokio::fs::remove_dir_all(&staging).await
    {
        rollback_errors.push(format!("remove staging directory: {error}"));
    }
    if was_running && let Err(error) = start_instance(&managed).await {
        rollback_errors.push(format!("restart original instance: {error}"));
    }
    if rollback_errors.is_empty() {
        Err(operation_error)
    } else {
        Err(fault(
            OpsErrorCode::Failed,
            format!(
                "{operation_error}; rollback also failed: {}",
                rollback_errors.join("; ")
            ),
        ))
    }
}

async fn stop_instance(managed: &Managed) -> Result<()> {
    managed.instance.stop().await?;
    wait_state(managed, InstanceState::Stopped).await
}

async fn start_instance(managed: &Managed) -> Result<()> {
    if let Err(error) = managed.instance.start().await {
        wait_terminal(managed).await?;
        return Err(error.into());
    }
    wait_state(managed, InstanceState::Running).await
}

async fn wait_terminal(managed: &Managed) -> Result<()> {
    let mut states = managed.instance.state_watch();
    timeout(OP_TIMEOUT, async {
        loop {
            let state = states.borrow_and_update().clone();
            if matches!(state, InstanceState::Stopped | InstanceState::Error(_)) {
                return Ok(());
            }
            states
                .changed()
                .await
                .context("instance supervisor stopped")?;
        }
    })
    .await
    .map_err(|_| fault(OpsErrorCode::Timeout, "instance failure state timed out"))?
}

async fn wait_state(managed: &Managed, expected: InstanceState) -> Result<()> {
    let mut states = managed.instance.state_watch();
    timeout(OP_TIMEOUT, async {
        loop {
            let state = states.borrow_and_update().clone();
            if state == expected {
                return Ok(());
            }
            if let InstanceState::Error(error) = state {
                return Err(fault(
                    OpsErrorCode::Failed,
                    format!("instance operation failed: {error}"),
                ));
            }
            states
                .changed()
                .await
                .context("instance supervisor stopped")?;
        }
    })
    .await
    .map_err(|_| fault(OpsErrorCode::Timeout, "instance operation timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rooms::InstanceConfig;
    use minecraftd::{
        core::event::TokioBroadcastBus,
        instance::{
            base::Instance, builder::InstanceBuilder, path::InstancePath, server::ServerConfig,
        },
        process::local::LocalSpawner,
        service::{instance::InstanceService, restart::RestartPolicy},
    };

    async fn console_fixture(directory: &Path, existing: usize) -> Result<Arc<Fleet>> {
        let config = InstanceConfig {
            id: "console".into(),
            directory: directory.join("instance"),
            backend: "127.0.0.1:25565".parse()?,
            server: ServerConfig {
                start_command:
                    r#"sh -c 'while IFS= read -r line; do printf "%s\n%s\n" "$line" "$line"; done'"#
                        .into(),
                ..Default::default()
            },
        };
        std::fs::create_dir_all(&config.directory)?;
        let mut instance =
            InstanceBuilder::new(config.id.clone(), InstancePath::new(&config.directory))
                .spawner(LocalSpawner::new())
                .event_bus(TokioBroadcastBus::new())
                .build_server(config.server.clone());
        instance.setup_output_ring(COMMAND_OUTPUT_LINES);
        let ring = instance
            .core
            .output_ring
            .as_ref()
            .context("missing output ring")?;
        for line in 0..existing {
            ring.push_str(&format!("old-{line}\n"));
        }
        let instance = InstanceService::new(instance, RestartPolicy::never());
        instance.start().await?;
        let managed = Managed {
            config,
            instance,
            operation: Arc::new(Mutex::new(())),
        };
        Ok(Arc::new(Fleet {
            instances: BTreeMap::from([("console".into(), Arc::new(managed))]),
            extended: Extended::new(
                directory.join("jobs.json"),
                directory.join("audit.jsonl"),
                ArchiveConfig {
                    base_dir: directory.join("archives"),
                    ..Default::default()
                },
            )?,
        }))
    }

    #[tokio::test]
    async fn command_after_saturated_ring_returns_only_two_new_lines() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fleet = console_fixture(directory.path(), COMMAND_OUTPUT_LINES).await?;
        let result = execute_command(&fleet, "console", "save-all").await;
        fleet.shutdown().await?;
        assert_eq!(result?, "save-all\nsave-all");
        Ok(())
    }

    #[tokio::test]
    async fn command_before_saturation_returns_only_two_new_lines() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fleet = console_fixture(directory.path(), 2).await?;
        let result = execute_command(&fleet, "console", "save-all").await;
        fleet.shutdown().await?;
        assert_eq!(result?, "save-all\nsave-all");
        Ok(())
    }

    #[tokio::test]
    async fn consecutive_commands_do_not_repeat_previous_output() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fleet = console_fixture(directory.path(), COMMAND_OUTPUT_LINES).await?;
        let first = execute_command(&fleet, "console", "first").await?;
        let second = execute_command(&fleet, "console", "second").await?;
        let repeated = execute_command(&fleet, "console", "second").await;
        fleet.shutdown().await?;
        assert_eq!(first, "first\nfirst");
        assert_eq!(second, "second\nsecond");
        assert_eq!(repeated?, "second\nsecond");
        Ok(())
    }

    #[test]
    fn command_output_uses_offsets_for_disjoint_and_dropped_windows() {
        let before_end = COMMAND_OUTPUT_LINES as u64;
        let after = vec!["same".into(); COMMAND_OUTPUT_LINES];
        assert_eq!(command_output_since(before_end, 0, &after), None);
        assert_eq!(
            command_output_since(before_end, before_end, &after),
            Some(after.join("\n"))
        );
        assert_eq!(
            command_output_since(before_end, before_end + 1, &after),
            Some(format!(
                "[output lines dropped before this window: 1]\n{}",
                after.join("\n")
            ))
        );
        assert_eq!(after.len(), COMMAND_OUTPUT_LINES);
        assert_eq!(command_output_since(before_end, before_end + 1, &[]), None);
    }
}
