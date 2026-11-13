use super::{
    Error, Result,
    capture::{Capture, Health},
    config::Config,
};
use crate::operation_contracts::{
    OperationsAction, OperationsBackupPage, OperationsCommand, OperationsInstance,
    OperationsInstanceState, OperationsJob, OperationsOperation, OperationsResult,
    OperationsSnapshot,
};
use minecraftd::{
    core::{
        event::{EventBus, InstanceEvent, TokioBroadcastBus},
        state::InstanceState,
    },
    instance::{builder::InstanceBuilder, path::InstancePath, server::ServerConfig},
    process::local::LocalSpawner,
    service::{instance::InstanceService, restart::RestartPolicy},
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, OwnedMutexGuard};

pub(super) struct Managed {
    pub service: InstanceService,
    pub gate: Arc<Mutex<()>>,
    released: AtomicBool,
    console: bool,
    pub expected_running: AtomicBool,
    pub health: Arc<Health>,
    prepared: Mutex<Option<super::backups::Prepared>>,
    deployment: Mutex<Option<super::deployment::Prepared>>,
    entry: super::deployment::Entry,
    pub ready: Arc<AtomicBool>,
    readiness_output: Arc<std::sync::Mutex<Vec<u8>>>,
}

const CLEANUP_RETRY_DELAY: Duration = Duration::from_secs(5);

pub(super) struct Fleet {
    instances: RwLock<BTreeMap<String, Arc<Managed>>>,
    gates: std::sync::Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    pub closing: AtomicBool,
    capture: Arc<Capture>,
    pub root: PathBuf,
    backups: super::backups::Backups,
    deployment: super::deployment::Deployment,
    profiles: BTreeMap<String, super::config::InstanceSettings>,
    jobs: Arc<super::jobs::Jobs>,
    spawner: LocalSpawner,
}

pub(super) fn directory(parent: &Path, name: &str) -> Result<PathBuf> {
    let path = parent.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
        Ok(_) => {
            return Err(Error::Invalid(
                "managed directory is not a directory or is a symlink".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&path)?,
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

impl Fleet {
    pub async fn start(config: &Config, jobs: &Arc<super::jobs::Jobs>) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data)?;
        let data = config.data.canonicalize()?;
        let root = directory(&data, "instances")?;
        let backups =
            super::backups::Backups::new(&data, config.backups.clone(), Arc::clone(jobs))?;
        let fleet = Arc::new(Self {
            instances: RwLock::new(BTreeMap::new()),
            gates: std::sync::Mutex::new(BTreeMap::new()),
            closing: AtomicBool::new(false),
            capture: Capture::start(Arc::clone(jobs)),
            root,
            backups,
            deployment: super::deployment::Deployment::new(
                &data,
                &config.artifact_origins,
                config.backups.clone(),
            )?,
            profiles: config.profiles.clone(),
            jobs: Arc::clone(jobs),
            spawner: LocalSpawner::with_group_observation()
                .map_err(|error| Error::Invalid(error.to_string()))?,
        });
        let initialized = async {
            for entry in std::fs::read_dir(&fleet.root)? {
                let entry = entry?;
                let id = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| Error::Invalid("invalid instance name".into()))?;
                super::config::identifier(&id)?;
                directory(&fleet.root, &id)?;
                fleet.backups.recover(&id, &entry.path()).await?;
                fleet.backups.reconcile(&id).await?;
                let definition = super::deployment::read_entry(&entry.path())?;
                let managed = fleet.manage(&id, definition)?;
                fleet
                    .instances
                    .write()
                    .map_err(|_| Error::StorageUnavailable)?
                    .insert(id, Arc::clone(&managed));
                if managed.entry.definition.auto_start {
                    managed.start().await?;
                }
            }
            Ok::<(), Error>(())
        }
        .await;
        if let Err(error) = initialized {
            return Err(error.with_recovery(fleet.close().await));
        }
        Ok(fleet)
    }

    fn manage(&self, id: &str, entry: super::deployment::Entry) -> Result<Arc<Managed>> {
        let settings = self
            .profiles
            .get(entry.definition.profile.as_str())
            .ok_or_else(|| Error::Invalid("unknown instance profile".into()))?;
        let bus = TokioBroadcastBus::new();
        let writer = Arc::clone(&self.capture);
        let health = Arc::new(Health::new(self.jobs.capture_lost(id)?));
        let output_health = Arc::clone(&health);
        let ready = Arc::new(AtomicBool::new(false));
        let output_ready = Arc::clone(&ready);
        let readiness_output = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let buffer = Arc::clone(&readiness_output);
        let marker = settings
            .readiness
            .as_ref()
            .map(|r| r.output.as_bytes().to_vec());
        bus.subscribe(
            "instance:output",
            Box::new(move |event| {
                if let Some(InstanceEvent::Output { instance_id, data }) =
                    event.as_any().downcast_ref::<InstanceEvent>()
                {
                    if let Some(marker) = &marker {
                        match buffer.lock() {
                            Ok(mut buffer) => {
                                buffer.extend_from_slice(data);
                                if buffer.windows(marker.len()).any(|part| part == marker) {
                                    output_ready.store(true, Ordering::SeqCst);
                                }
                                let drop = buffer.len().saturating_sub(marker.len());
                                buffer.drain(..drop);
                            }
                            Err(_) => output_health.failed.store(true, Ordering::SeqCst),
                        }
                    }
                    match super::now() {
                        Ok(at) => writer.submit(instance_id, data, at, &output_health),
                        Err(error) => {
                            output_health.lost.store(true, Ordering::SeqCst);
                            if !output_health.failed.swap(true, Ordering::SeqCst) {
                                tracing::error!(%error,"managed output timestamp failed");
                            }
                        }
                    }
                }
            }),
        );
        let instance = InstanceBuilder::new(id.into(), InstancePath::new(self.root.join(id)))
            .spawner(self.spawner.clone())
            .event_bus(bus)
            .build_server(ServerConfig {
                start_command: settings.start_command.clone(),
                stop_command: settings.stop_command.clone(),
                server_type: settings.kind.server_type().into(),
                ..Default::default()
            });
        Ok(Arc::new(Managed {
            service: InstanceService::new(instance, RestartPolicy::never()),
            gate: self.gate_for(id)?,
            released: AtomicBool::new(false),
            console: settings.kind.server_type() != "universal",
            expected_running: AtomicBool::new(entry.definition.auto_start),
            health,
            prepared: Mutex::new(None),
            deployment: Mutex::new(None),
            entry,
            ready,
            readiness_output,
        }))
    }
    pub fn instance(&self, id: &str) -> Result<Arc<Managed>> {
        self.instances
            .read()
            .map_err(|_| Error::StorageUnavailable)?
            .get(id)
            .cloned()
            .ok_or_else(|| Error::Invalid("unknown managed instance".into()))
    }
    pub async fn gate(&self, id: &str) -> Result<OwnedMutexGuard<()>> {
        let gate = self.gate_for(id)?;
        Ok(gate.lock_owned().await)
    }
    fn gate_for(&self, id: &str) -> Result<Arc<Mutex<()>>> {
        super::config::identifier(id)?;
        Ok(Arc::clone(
            self.gates
                .lock()
                .map_err(|_| Error::StorageUnavailable)?
                .entry(id.into())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        ))
    }
    fn all(&self) -> Result<Vec<(String, Arc<Managed>)>> {
        Ok(self
            .instances
            .read()
            .map_err(|_| Error::StorageUnavailable)?
            .iter()
            .map(|(id, m)| (id.clone(), Arc::clone(m)))
            .collect())
    }
    pub async fn backups(&self, instance: &str, scope: &str) -> Result<OperationsBackupPage> {
        let _guard = self.gate(instance).await?;
        self.backups.list(instance, scope).await
    }
    pub async fn apply(
        &self,
        job: &OperationsJob,
        authority: &super::authority::Authority,
    ) -> Result<OperationsResult> {
        let command: &OperationsCommand = &job.intent.command;
        let scope = &job.intent.scope;
        let id = command.instance.to_string();
        let root = self.root.join(&id);
        let mut result = OperationsResult {
            backup: None,
            safety_archive: None,
        };
        if self.closing.load(Ordering::SeqCst) {
            return Err(Error::Invalid("supervisor is stopping".into()));
        }
        if let OperationsOperation::Provision(operation) = &command.operation {
            return self.provision(job, operation, authority).await;
        }
        let managed = self.instance(&command.instance.to_string())?;
        let service = &managed.service;
        if self.backups.pending(&id)?
            && !(matches!(&command.operation, OperationsOperation::Kill(_))
                || matches!(&command.operation,OperationsOperation::Lifecycle(operation) if matches!(operation.action,OperationsAction::Stop)))
        {
            return Err(Error::Invalid(
                "unfinished activation requires supervisor recovery".into(),
            ));
        }
        if matches!(
            command.operation,
            OperationsOperation::Lifecycle(_)
                | OperationsOperation::Console(_)
                | OperationsOperation::Kill(_)
                | OperationsOperation::BackupCreate(_)
        ) && managed.prepared.lock().await.take().is_some()
        {
            self.backups.discard(&id).await?;
        }
        match &command.operation {
            OperationsOperation::Provision(_) => return Err(Error::Conflict),
            OperationsOperation::DeployPrepare(operation) => {
                self.profile(&managed)?.readiness.as_ref().ok_or_else(|| {
                    Error::Invalid("deployment requires profile readiness settings".into())
                })?;
                if let Some(previous) = managed.deployment.lock().await.take() {
                    std::fs::remove_dir_all(previous.directory)?;
                }
                let directory = self
                    .deployment
                    .prepare(&job.intent.id.to_string(), &operation.changes)
                    .await?;
                if let Err(error) = authority.authorize(job).await {
                    return Err(error
                        .with_recovery(std::fs::remove_dir_all(&directory).map_err(Error::from)));
                }
                *managed.deployment.lock().await = Some(super::deployment::Prepared {
                    request: job.intent.id.to_string(),
                    scope: scope.clone(),
                    directory,
                });
            }
            OperationsOperation::Deploy(operation) => {
                return self
                    .deploy(job, &managed, &operation.preparation.to_string(), authority)
                    .await;
            }
            OperationsOperation::InstanceDelete(_) => {
                authority.authorize(job).await?;
                managed.prepared.lock().await.take();
                self.backups.discard(&id).await?;
                if let Some(prepared) = managed.deployment.lock().await.take() {
                    std::fs::remove_dir_all(prepared.directory)?;
                }
                let running = matches!(service.state(), InstanceState::Running);
                let deleted = async {
                    Self::quiesce(&managed).await?;
                    let safety = self
                        .backups
                        .create(
                            &id,
                            scope,
                            &root,
                            &format!("before deletion {}", *job.intent.id),
                        )
                        .await?;
                    let removed = self.deployment.removed.join(&id);
                    std::fs::rename(&root, &removed)?;
                    std::fs::File::open(&self.root)?.sync_all()?;
                    std::fs::File::open(&self.deployment.removed)?.sync_all()?;
                    self.instances
                        .write()
                        .map_err(|_| Error::StorageUnavailable)?
                        .remove(&id);
                    managed.service.shutdown().await?;
                    let cleanup = removed.clone();
                    tokio::task::spawn_blocking(move || std::fs::remove_dir_all(cleanup)).await??;
                    result.safety_archive = Some(super::config::identifier(&safety.id)?);
                    Ok::<(), Error>(())
                }
                .await;
                if let Err(error) = deleted {
                    let recovery = if root.try_exists()? {
                        Self::resume(&managed, running).await
                    } else {
                        Ok(())
                    };
                    return Err(error.with_recovery(recovery));
                }
            }
            OperationsOperation::Lifecycle(operation) => {
                match operation.action {
                    OperationsAction::Start => managed.start().await?,
                    OperationsAction::Stop => {
                        service.stop_gracefully().await?;
                    }
                    OperationsAction::Restart => {
                        service.stop_gracefully().await?;
                        managed.start().await?;
                    }
                }
                managed.expected_running.store(
                    !matches!(operation.action, OperationsAction::Stop),
                    Ordering::SeqCst,
                );
            }
            OperationsOperation::Kill(operation) => {
                if service.process_id().await.map(u64::from) != Some(operation.pid.into()) {
                    return Err(Error::Conflict);
                }
                service.kill().await?;
                managed.expected_running.store(false, Ordering::SeqCst);
            }
            OperationsOperation::BackupCreate(operation) => {
                let running = matches!(service.state(), InstanceState::Running);
                if let Err(error) = Self::quiesce(&managed).await {
                    return Err(error.with_recovery(Self::resume(&managed, running).await));
                }
                let created = self
                    .backups
                    .create(&id, scope, &root, &operation.label)
                    .await;
                let resumed = Self::resume(&managed, running).await;
                let record = match (created, resumed) {
                    (Ok(record), Ok(())) => record,
                    (Err(error), recovery) => return Err(error.with_recovery(recovery)),
                    (Ok(_), Err(error)) => return Err(error),
                };
                result.backup = Some(super::backups::receipt(&record)?);
            }
            OperationsOperation::RestorePrepare(operation) => {
                managed.prepared.lock().await.take();
                self.backups.discard(&id).await?;
                let (archive, transaction) = self
                    .backups
                    .prepare(&id, scope, &operation.archive.to_string(), &root)
                    .await?;
                let definition =
                    super::deployment::read_entry(&super::deployment::candidate(&transaction))
                        .and_then(|entry| {
                            if serde_json::to_value(&entry.definition)?
                                != serde_json::to_value(&managed.entry.definition)?
                            {
                                return Err(Error::Invalid(
                                    "restore instance definition differs from the managed instance"
                                        .into(),
                                ));
                            }
                            Ok(())
                        });
                if let Err(error) = definition {
                    return Err(error.with_recovery(self.backups.discard(&id).await));
                }
                if let Err(error) = authority.authorize(job).await {
                    return Err(error.with_recovery(self.backups.discard(&id).await));
                }
                result.backup = Some(super::backups::receipt(&archive)?);
                *managed.prepared.lock().await = Some(super::backups::Prepared {
                    archive,
                    scope: scope.clone(),
                    request: job.intent.id.to_string(),
                    transaction,
                });
            }
            OperationsOperation::Restore(operation) => {
                authority.authorize(job).await?;
                let prepared = {
                    let preparation = managed.prepared.lock().await;
                    let prepared = preparation.as_ref().ok_or_else(|| {
                        Error::Invalid("prepare this restore before requesting confirmation".into())
                    })?;
                    if prepared.archive.id != operation.archive.to_string()
                        || prepared.request != operation.preparation.to_string()
                        || prepared.scope != *scope
                    {
                        return Err(Error::Conflict);
                    }
                    prepared.clone()
                };
                let resume = matches!(service.state(), InstanceState::Running);
                if let Err(error) = Self::quiesce(&managed).await {
                    return Err(error.with_recovery(Self::resume(&managed, resume).await));
                }
                let safety = match self
                    .backups
                    .create(
                        &id,
                        scope,
                        &root,
                        &format!("before restore {}", *job.intent.id),
                    )
                    .await
                {
                    Ok(safety) => safety,
                    Err(error) => {
                        return Err(error.with_recovery(Self::resume(&managed, resume).await));
                    }
                };
                managed.prepared.lock().await.take();
                if let Err(error) = self
                    .backups
                    .activate(&prepared.transaction, &root, &safety.id)
                {
                    let recovery = async {
                        self.backups.recover(&id, &root).await?;
                        Self::resume(&managed, resume).await
                    }
                    .await;
                    return Err(error.with_recovery(recovery));
                }
                let started = async {
                    if resume {
                        managed.start().await?;
                        if self.profile(&managed)?.readiness.is_some() {
                            super::deployment::healthy(&managed, self.profile(&managed)?).await?;
                        }
                    }
                    Ok::<(), Error>(())
                }
                .await;
                if let Err(error) = started {
                    let recovery = async {
                        Self::quiesce(&managed).await?;
                        self.backups.recover(&id, &root).await?;
                        Self::resume(&managed, true).await
                    }
                    .await;
                    return Err(error.with_recovery(recovery));
                }
                managed.expected_running.store(resume, Ordering::SeqCst);
                self.backups.commit(&prepared.transaction).await?;
                result.backup = Some(super::backups::receipt(&prepared.archive)?);
                result.safety_archive = Some(super::config::identifier(&safety.id)?);
            }
            OperationsOperation::BackupExport(operation) => {
                result.backup = Some(
                    self.backups
                        .export(
                            &id,
                            scope,
                            &operation.archive.to_string(),
                            &job.intent.id.to_string(),
                        )
                        .await?,
                );
            }
            OperationsOperation::BackupImport(operation) => {
                result.backup = Some(
                    self.backups
                        .import(
                            &id,
                            scope,
                            &operation.archive.to_string(),
                            &job.intent.id.to_string(),
                        )
                        .await?,
                );
            }
            OperationsOperation::BackupDelete(operation) => {
                result.backup = Some(
                    self.backups
                        .delete(&id, scope, &operation.archive.to_string())
                        .await?,
                );
            }
            OperationsOperation::Console(operation) => {
                if !managed.console {
                    return Err(Error::Invalid(
                        "console input is disabled for services".into(),
                    ));
                }
                service.send_command(operation.input.to_string()).await?;
            }
        }
        Ok(result)
    }

    fn profile(&self, managed: &Managed) -> Result<&super::config::InstanceSettings> {
        self.profiles
            .get(managed.entry.definition.profile.as_str())
            .ok_or_else(|| Error::Invalid("unknown instance profile".into()))
    }

    async fn provision(
        &self,
        job: &OperationsJob,
        operation: &crate::operation_contracts::OperationsProvision,
        authority: &super::authority::Authority,
    ) -> Result<OperationsResult> {
        let id = job.intent.command.instance.to_string();
        let root = self.root.join(&id);
        if root.try_exists()?
            || self
                .instances
                .read()
                .map_err(|_| Error::StorageUnavailable)?
                .contains_key(&id)
        {
            return Err(Error::Conflict);
        }
        let profile = self
            .profiles
            .get(operation.profile.as_str())
            .ok_or_else(|| Error::Invalid("unknown instance profile".into()))?;
        if operation.auto_start && profile.readiness.is_none() {
            return Err(Error::Invalid(
                "automatic provisioning requires readiness settings".into(),
            ));
        }
        let stage = self
            .deployment
            .prepare(&job.intent.id.to_string(), &operation.changes)
            .await?;
        let result = async {
            let candidate = directory(&stage, "instance")?;
            self.deployment.apply(&stage, &candidate).await?;
            let entry = super::deployment::Entry {
                definition: crate::operation_contracts::OperationsDefinition {
                    profile: operation.profile.clone(),
                    auto_start: operation.auto_start,
                },
            };
            super::deployment::write_entry(&candidate, &entry)?;
            authority.authorize(job).await?;
            std::fs::rename(&candidate, &root)?;
            std::fs::File::open(&self.root)?.sync_all()?;
            std::fs::File::open(&stage)?.sync_all()?;
            let managed = self.manage(&id, entry)?;
            self.instances
                .write()
                .map_err(|_| Error::StorageUnavailable)?
                .insert(id.clone(), Arc::clone(&managed));
            if operation.auto_start {
                let started = async {
                    managed.start().await?;
                    super::deployment::healthy(&managed, profile).await
                }
                .await;
                if let Err(error) = started {
                    let recovery = async {
                        Self::quiesce(&managed).await?;
                        managed.service.shutdown().await?;
                        std::fs::rename(&root, &candidate)?;
                        std::fs::File::open(&self.root)?.sync_all()?;
                        std::fs::File::open(&stage)?.sync_all()?;
                        self.instances
                            .write()
                            .map_err(|_| Error::StorageUnavailable)?
                            .remove(&id);
                        Ok(())
                    }
                    .await;
                    return Err(error.with_recovery(recovery));
                }
            }
            Ok(OperationsResult {
                backup: None,
                safety_archive: None,
            })
        }
        .await;
        let cleanup = std::fs::remove_dir_all(stage).map_err(Error::from);
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), cleanup) => Err(error.with_recovery(cleanup)),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    async fn deploy(
        &self,
        job: &OperationsJob,
        managed: &Managed,
        preparation: &str,
        authority: &super::authority::Authority,
    ) -> Result<OperationsResult> {
        let prepared = managed
            .deployment
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| Error::Invalid("prepare this deployment before confirmation".into()))?;
        if prepared.request != preparation || prepared.scope != job.intent.scope {
            return Err(Error::Conflict);
        }
        let profile = self.profile(managed)?;
        if profile.readiness.is_none() {
            return Err(Error::Invalid(
                "deployment requires profile readiness settings".into(),
            ));
        }
        let id = job.intent.command.instance.to_string();
        let root = self.root.join(&id);
        authority.authorize(job).await?;
        managed.prepared.lock().await.take();
        let running = matches!(managed.service.state(), InstanceState::Running);
        if let Err(error) = Self::quiesce(managed).await {
            return Err(error.with_recovery(Self::resume(managed, running).await));
        }
        let safety = match self
            .backups
            .create(
                &id,
                &job.intent.scope,
                &root,
                &format!("before deployment {}", *job.intent.id),
            )
            .await
        {
            Ok(safety) => safety,
            Err(error) => return Err(error.with_recovery(Self::resume(managed, running).await)),
        };
        let updated = async {
            let (_, transaction) = self
                .backups
                .prepare(&id, &job.intent.scope, &safety.id, &root)
                .await?;
            self.deployment
                .apply(
                    &prepared.directory,
                    &super::deployment::candidate(&transaction),
                )
                .await?;
            self.backups.activate(&transaction, &root, &safety.id)?;
            managed.start().await?;
            super::deployment::healthy(managed, profile).await?;
            if !running {
                Self::quiesce(managed).await?;
            }
            Ok::<_, Error>(transaction)
        }
        .await;
        let transaction = match updated {
            Ok(transaction) => transaction,
            Err(error) => {
                let recovery = async {
                    Self::quiesce(managed).await?;
                    self.backups.recover(&id, &root).await?;
                    Self::resume(managed, running).await?;
                    if running {
                        super::deployment::healthy(managed, profile).await?;
                    }
                    Ok(())
                }
                .await;
                return Err(error.with_recovery(recovery));
            }
        };
        self.backups.commit(&transaction).await?;
        managed.deployment.lock().await.take();
        std::fs::remove_dir_all(&prepared.directory)?;
        managed.expected_running.store(running, Ordering::SeqCst);
        Ok(OperationsResult {
            backup: None,
            safety_archive: Some(super::config::identifier(&safety.id)?),
        })
    }

    async fn resume(managed: &Managed, running: bool) -> Result<()> {
        if running && managed.service.process_id().await.is_none() {
            managed.start().await?;
            managed.expected_running.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    async fn quiesce(managed: &Managed) -> Result<()> {
        let exit = managed.service.stop_gracefully().await?;
        if exit.is_some_and(|code| code != 0) {
            return Err(Error::Invalid(
                "instance did not complete a clean shutdown".into(),
            ));
        }
        Ok(())
    }

    pub async fn snapshot(&self) -> Result<OperationsSnapshot> {
        let mut instances = Vec::new();
        for (id, managed) in self.all()? {
            let state = match managed.service.state() {
                InstanceState::Stopped => OperationsInstanceState::Stopped,
                InstanceState::Starting => OperationsInstanceState::Starting,
                InstanceState::Running => OperationsInstanceState::Running,
                InstanceState::Stopping => OperationsInstanceState::Stopping,
                InstanceState::Busy => OperationsInstanceState::Busy,
                InstanceState::Error(_) => OperationsInstanceState::Error,
            };
            instances.push(OperationsInstance {
                id: super::config::identifier(&id)?,
                accepts_console: managed.console,
                state,
                pid: managed.service.process_id().await.map(u64::from),
            });
        }
        Ok(OperationsSnapshot { instances })
    }

    pub async fn close(&self) -> Result<()> {
        self.closing.store(true, Ordering::SeqCst);
        loop {
            let mut complete = true;
            for (id, managed) in self.all()? {
                let _guard = managed.gate.lock().await;
                if managed.released.load(Ordering::SeqCst) {
                    continue;
                }
                match managed.service.shutdown().await {
                    Ok(()) => managed.released.store(true, Ordering::SeqCst),
                    Err(error) => {
                        tracing::error!(%id, %error, "managed instance shutdown failed; retaining ownership for retry");
                        complete = false;
                    }
                }
            }
            if complete {
                return self.capture.finish().await;
            }
            tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
        }
    }
}

impl Managed {
    async fn start(&self) -> Result<()> {
        self.ready.store(false, Ordering::SeqCst);
        self.readiness_output
            .lock()
            .map_err(|_| Error::StorageUnavailable)?
            .clear();
        self.service.start().await?;
        Ok(())
    }
}
