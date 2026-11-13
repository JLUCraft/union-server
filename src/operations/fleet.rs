use super::{
    Error, Result,
    capture::{Capture, Health},
    config::Config,
};
use crate::operation_contracts::{
    OperationsAction, OperationsCommand, OperationsInstance, OperationsInstanceState,
    OperationsOperation, OperationsSnapshot,
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
}

const CLEANUP_RETRY_DELAY: Duration = Duration::from_secs(5);

pub(super) struct Fleet {
    pub instances: BTreeMap<String, Managed>,
    pub closing: AtomicBool,
    capture: Arc<Capture>,
    pub root: PathBuf,
}

fn directory(parent: &Path, name: &str) -> Result<PathBuf> {
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
    Ok(path)
}

impl Fleet {
    pub async fn start(config: &Config, jobs: &Arc<super::jobs::Jobs>) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data)?;
        let data = config.data.canonicalize()?;
        let root = directory(&data, "instances")?;
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
                },
            );
        }
        let fleet = Arc::new(Self {
            instances,
            closing: AtomicBool::new(false),
            capture,
            root,
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

    pub async fn apply(&self, command: &OperationsCommand) -> Result<()> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(Error::Invalid("supervisor is stopping".into()));
        }
        let managed = self.instance(&command.instance.to_string())?;
        let service = &managed.service;
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
            OperationsOperation::Console(operation) => {
                if !managed.console {
                    return Err(Error::Invalid(
                        "console input is disabled for services".into(),
                    ));
                }
                service.send_command(operation.input.to_string()).await?;
            }
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
