//! Frozen operations instance helpers. Excluded from the central host build.
use anyhow::{Context, Result, ensure};
use minecraftd::{core::{event::TokioBroadcastBus, state::InstanceState}, instance::{builder::InstanceBuilder, path::InstancePath, server::ServerConfig}, process::local::LocalSpawner, service::{instance::InstanceService, restart::RestartPolicy}};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::time::timeout;
const STOP_TIMEOUT: Duration = Duration::from_secs(20);
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    pub id: String,
    pub directory: PathBuf,
    pub backend: SocketAddr,
    pub server: ServerConfig,
}
impl InstanceConfig {
    pub fn validate(&self) -> crate::Result<()> {
        self.validate_inner().map_err(crate::operation_error)
    }
    fn validate_inner(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty() && self.id.len() <= 128,
            "invalid instance id"
        );
        ensure!(self.directory.is_dir(), "instance directory is missing");
        ensure!(
            self.backend.ip().is_loopback() && self.backend.port() != 0,
            "backend must use a fixed loopback port"
        );
        ensure!(
            !self.server.start_command.trim().is_empty(),
            "start command is missing"
        );
        ensure!(
            self.server.auto_restart_max_times >= -1,
            "auto restart maximum must be -1 or greater"
        );
        Ok(())
    }
    pub fn create(&self) -> crate::Result<InstanceService> {
        self.create_inner().map_err(crate::operation_error)
    }
    fn create_inner(&self) -> Result<InstanceService> {
        self.validate()?;
        Ok(InstanceService::new(
            InstanceBuilder::new(self.id.clone(), InstancePath::new(&self.directory))
                .spawner(LocalSpawner::new())
                .event_bus(TokioBroadcastBus::new())
                .build_server(self.server.clone()),
            RestartPolicy {
                enabled: self.server.auto_restart,
                max_retries: self.server.auto_restart_max_times,
                ..RestartPolicy::default()
            },
        ))
    }
}

pub async fn shutdown_instance(instance: &InstanceService) -> crate::Result<()> {
    shutdown_instance_inner(instance)
        .await
        .map_err(crate::operation_error)
}
async fn shutdown_instance_inner(instance: &InstanceService) -> Result<()> {
    let mut states = instance.state_watch();
    instance.shutdown().await?;
    timeout(STOP_TIMEOUT, async {
        while states.changed().await.is_ok() {}
    })
    .await
    .context("instance shutdown timed out")?;
    Ok(())
}
