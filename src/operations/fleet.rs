use super::{Error, Result, config::Config};
use crate::operation_contracts::{
    OperationsAction, OperationsCommand, OperationsInstance, OperationsInstanceState,
    OperationsSnapshot,
};
use minecraftd::{
    core::{event::TokioBroadcastBus, state::InstanceState},
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
}

const CLEANUP_RETRY_DELAY: Duration = Duration::from_secs(5);

pub(super) struct Fleet {
    pub instances: BTreeMap<String, Managed>,
    pub closing: AtomicBool,
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
    pub async fn start(config: &Config) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data)?;
        let data = config.data.canonicalize()?;
        let root = directory(&data, "instances")?;
        let mut instances = BTreeMap::new();
        for (id, settings) in &config.instances {
            let path = directory(&root, id)?;
            let instance = InstanceBuilder::new(id.clone(), InstancePath::new(path))
                .spawner(LocalSpawner::new())
                .event_bus(TokioBroadcastBus::new())
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
                },
            );
        }
        let fleet = Arc::new(Self {
            instances,
            closing: AtomicBool::new(false),
        });
        for (id, settings) in &config.instances {
            if settings.auto_start {
                let result = fleet.instance(id)?.service.start().await;
                if let Err(error) = result {
                    fleet.close().await;
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
        let service = &self.instance(&command.instance.to_string())?.service;
        match command.action {
            OperationsAction::Start => service.start().await?,
            OperationsAction::Stop => service.stop().await?,
            OperationsAction::Restart => service.restart().await?,
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
                state,
                pid: managed.service.process_id().await.map(u64::from),
            });
        }
        Ok(OperationsSnapshot { instances })
    }

    pub async fn close(&self) {
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
                return;
            }
            tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
        }
    }
}
