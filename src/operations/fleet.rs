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
        Arc,
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
}

const CLEANUP_RETRY_DELAY: Duration = Duration::from_secs(5);

pub(super) struct Fleet {
    pub instances: BTreeMap<String, Managed>,
    pub closing: AtomicBool,
    capture: Arc<Capture>,
    pub root: PathBuf,
    backups: super::backups::Backups,
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
        for id in config.instances.keys() {
            backups.recover(id, &root.join(id)).await?;
            backups.reconcile(id).await?;
        }
        let mut instances = BTreeMap::new();
        let spawner = LocalSpawner::with_group_observation()
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let capture = Capture::start(Arc::clone(jobs));
        for (id, settings) in &config.instances {
            let path = directory(&root, id)?;
            let bus = TokioBroadcastBus::new();
            let writer = Arc::clone(&capture);
            let health = Arc::new(Health::new(jobs.capture_lost(id)?));
            let output_health = Arc::clone(&health);
            bus.subscribe(
                "instance:output",
                Box::new(move |event| {
                    if let Some(InstanceEvent::Output { instance_id, data }) =
                        event.as_any().downcast_ref::<InstanceEvent>()
                    {
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
            let instance = InstanceBuilder::new(id.clone(), InstancePath::new(path))
                .spawner(spawner.clone())
                .event_bus(bus)
                .build_server(ServerConfig {
                    start_command: settings.start_command.clone(),
                    stop_command: settings.stop_command.clone(),
                    server_type: settings.kind.server_type().into(),
                    ..Default::default()
                });
            instances.insert(
                id.clone(),
                Managed {
                    service: InstanceService::new(instance, RestartPolicy::never()),
                    gate: Arc::new(Mutex::new(())),
                    released: AtomicBool::new(false),
                    console: settings.kind.server_type() != "universal",
                    expected_running: AtomicBool::new(settings.auto_start),
                    health,
                    prepared: Mutex::new(None),
                },
            );
        }
        let fleet = Arc::new(Self {
            instances,
            closing: AtomicBool::new(false),
            capture,
            root,
            backups,
        });
        for (id, settings) in &config.instances {
            if settings.auto_start {
                let result = fleet.instance(id)?.service.start().await;
                if let Err(error) = result {
                    if let Err(cleanup) = fleet.close().await {
                        tracing::error!(%cleanup,"supervisor startup capture cleanup failed");
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(fleet)
    }

    pub fn instance(&self, id: &str) -> Result<&Managed> {
        self.instances
            .get(id)
            .ok_or_else(|| Error::Invalid("unknown managed instance".into()))
    }

    pub async fn gate(&self, id: &str) -> Result<OwnedMutexGuard<()>> {
        Ok(self.instance(id)?.gate.clone().lock_owned().await)
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
        let managed = self.instance(&command.instance.to_string())?;
        let service = &managed.service;
        if matches!(
            command.operation,
            OperationsOperation::Lifecycle(_)
                | OperationsOperation::Console(_)
                | OperationsOperation::Kill(_)
                | OperationsOperation::BackupCreate(_)
        ) {
            if managed.prepared.lock().await.take().is_some() {
                self.backups.discard(&id).await?;
            }
            if self.backups.pending(&id)?
                && !(matches!(&command.operation, OperationsOperation::Kill(_))
                    || matches!(&command.operation,OperationsOperation::Lifecycle(operation) if matches!(operation.action,OperationsAction::Stop)))
            {
                return Err(Error::Invalid(
                    "unfinished restore requires supervisor recovery".into(),
                ));
            }
        }
        match &command.operation {
            OperationsOperation::Lifecycle(operation) => {
                match operation.action {
                    OperationsAction::Start => service.start().await?,
                    OperationsAction::Stop => {
                        service.stop_gracefully().await?;
                    }
                    OperationsAction::Restart => {
                        service.stop_gracefully().await?;
                        service.start().await?;
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
                if let Err(error) = Self::quiesce(managed).await {
                    return Err(error.with_recovery(Self::resume(managed, running).await));
                }
                let created = self
                    .backups
                    .create(&id, scope, &root, &operation.label)
                    .await;
                let resumed = Self::resume(managed, running).await;
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
                authority.authorize(job).await?;
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
                if let Err(error) = Self::quiesce(managed).await {
                    return Err(error.with_recovery(Self::resume(managed, resume).await));
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
                        return Err(error.with_recovery(Self::resume(managed, resume).await));
                    }
                };
                managed.prepared.lock().await.take();
                if let Err(error) = self
                    .backups
                    .activate(&prepared.transaction, &root, &safety.id)
                {
                    let recovery = async {
                        self.backups.recover(&id, &root).await?;
                        Self::resume(managed, resume).await
                    }
                    .await;
                    return Err(error.with_recovery(recovery));
                }
                if resume && let Err(error) = service.start().await {
                    let recovery = async {
                        Self::quiesce(managed).await?;
                        self.backups.recover(&id, &root).await?;
                        Self::resume(managed, true).await
                    }
                    .await;
                    return Err(Error::from(error).with_recovery(recovery));
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

    async fn resume(managed: &Managed, running: bool) -> Result<()> {
        if running && managed.service.process_id().await.is_none() {
            managed.service.start().await?;
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
        for (id, managed) in &self.instances {
            let state = match managed.service.state() {
                InstanceState::Stopped => OperationsInstanceState::Stopped,
                InstanceState::Starting => OperationsInstanceState::Starting,
                InstanceState::Running => OperationsInstanceState::Running,
                InstanceState::Stopping => OperationsInstanceState::Stopping,
                InstanceState::Busy => OperationsInstanceState::Busy,
                InstanceState::Error(_) => OperationsInstanceState::Error,
            };
            instances.push(OperationsInstance {
                id: super::config::identifier(id)?,
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
            for (id, managed) in &self.instances {
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
