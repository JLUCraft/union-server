//! Identity-authorized operations over locally configured instances.
use crate::rooms::{InstanceConfig, shutdown_instance};
use anyhow::{Context, Result, ensure};
use minecraftd::{core::state::InstanceState, service::instance::InstanceService};
use node::{
    Node, ServiceId,
    protocol::{
        JsonFrame, OpsInstance, OpsInstanceState, OpsOp, OpsRequest, OpsResponse, read_frame,
        write_frame,
    },
};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::Mutex, task::JoinSet, time::timeout};

pub(crate) const MAX_INSTANCES: usize = 32;
const OP_TIMEOUT: Duration = Duration::from_secs(120);
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const LOG_LINES: usize = 100;
const LOG_BYTES: usize = 8 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub instances: Vec<InstanceConfig>,
    #[serde(default = "default_state_path")]
    pub state: PathBuf,
    #[serde(default = "default_audit_path")]
    pub audit: PathBuf,
    #[serde(default)]
    pub archives: minecraftd::archive::manager::ArchiveConfig,
}

pub(crate) fn default_state_path() -> PathBuf {
    "operations-jobs.json".into()
}
pub(crate) fn default_audit_path() -> PathBuf {
    "operations-audit.jsonl".into()
}

pub(crate) struct Managed {
    pub(crate) config: InstanceConfig,
    pub(crate) instance: InstanceService,
    pub(crate) operation: Arc<Mutex<()>>,
}

pub struct Fleet {
    pub(crate) instances: BTreeMap<String, Arc<Managed>>,
    pub(crate) extended: crate::ops_extended::Extended,
}
impl Fleet {
    pub fn new(config: Config) -> crate::Result<Self> {
        Self::new_inner(config).map_err(crate::operation_error)
    }
    fn new_inner(config: Config) -> Result<Self> {
        ensure!(
            config.instances.len() <= MAX_INSTANCES,
            "at most 32 configured instances"
        );
        ensure!(
            config.state != config.audit,
            "operations state and audit paths collide"
        );
        std::fs::create_dir_all(&config.archives.base_dir)?;
        let archive_root = config.archives.base_dir.canonicalize()?;
        for instance in &config.instances {
            let instance_root = instance.directory.canonicalize()?;
            ensure!(
                !archive_root.starts_with(&instance_root)
                    && !instance_root.starts_with(&archive_root),
                "archive and instance directories must be disjoint"
            );
        }
        let extended =
            crate::ops_extended::Extended::new(config.state, config.audit, config.archives)?;
        let mut instances = BTreeMap::new();
        for config in config.instances {
            ensure!(!instances.contains_key(&config.id), "duplicate instance id");
            let instance = config.create()?;
            instances.insert(
                config.id.clone(),
                Arc::new(Managed {
                    config,
                    instance,
                    operation: Arc::new(Mutex::new(())),
                }),
            );
        }
        Ok(Self {
            instances,
            extended,
        })
    }
    pub async fn execute(
        self: &Arc<Self>,
        request: OpsRequest,
        actor: &str,
    ) -> crate::Result<OpsResponse> {
        self.execute_tracked(request, actor)
            .await
            .map_err(crate::operation_error)
    }
    async fn execute_tracked(
        self: &Arc<Self>,
        request: OpsRequest,
        actor: &str,
    ) -> Result<OpsResponse> {
        if crate::ops_extended::is_extended(&request.op) {
            return crate::ops_extended::execute(self, request, actor).await;
        }
        let result = self.execute_inner(request.clone()).await;
        let audit_response = result.as_ref().map_or_else(
            |error| OpsResponse {
                ok: false,
                error: Some(crate::ops_extended::error_response(error)),
                ..Default::default()
            },
            |response| response.clone(),
        );
        crate::ops_extended::audit_legacy(self, &request, actor, &audit_response).await?;
        result
    }
    async fn execute_inner(&self, request: OpsRequest) -> Result<OpsResponse> {
        if let OpsOp::ListInstances {} = request.op {
            let mut instances = Vec::new();
            for managed in self.instances.values() {
                instances.push(status(managed).await?);
            }
            return Ok(OpsResponse {
                ok: true,
                instances,
                ..Default::default()
            });
        }
        let id = match &request.op {
            OpsOp::Status { instance }
            | OpsOp::Start { instance }
            | OpsOp::StartLeague { instance, .. }
            | OpsOp::StopLeague { instance, .. }
            | OpsOp::Stop { instance }
            | OpsOp::Restart { instance }
            | OpsOp::Kill { instance }
            | OpsOp::Logs { instance } => instance,
            OpsOp::ListInstances {} => anyhow::bail!("list operation has no instance"),
            _ => anyhow::bail!("extended operation dispatched through legacy path"),
        };
        let managed = self.instances.get(id).ok_or_else(|| {
            crate::ops_extended::fault(node::protocol::OpsErrorCode::NotFound, "unknown instance")
        })?;
        let _operation = managed.operation.try_lock().map_err(|_| {
            crate::ops_extended::fault(
                node::protocol::OpsErrorCode::Busy,
                "instance operation already in progress",
            )
        })?;
        if let OpsOp::StartLeague { league, .. } | OpsOp::StopLeague { league, .. } = &request.op {
            node::protocol::validate_identifier(league)?;
            let marker = managed
                .config
                .directory
                .join(node::protocol::GAME_SESSION_FILE);
            let existing = std::fs::read(&marker).ok().and_then(|bytes| {
                serde_json::from_slice::<node::protocol::GameSession>(&bytes).ok()
            });
            let binding = node::protocol::GameSession {
                protocol_version: node::protocol::GAME_ADAPTER_VERSION,
                league: league.clone(),
            };
            if matches!(&request.op, OpsOp::StartLeague { .. }) {
                if matches!(
                    managed.instance.state(),
                    InstanceState::Stopped | InstanceState::Error(_)
                ) {
                    let directory = marker.parent().context("instance directory missing")?;
                    std::fs::create_dir_all(directory)?;
                    let pending = marker.with_extension("pending");
                    std::fs::write(&pending, serde_json::to_vec(&binding)?)?;
                    std::fs::rename(pending, &marker)?;
                } else {
                    ensure!(
                        existing.as_ref() == Some(&binding),
                        "instance belongs to another activity"
                    );
                    return Ok(OpsResponse {
                        ok: true,
                        instances: vec![status(managed).await?],
                        ..Default::default()
                    });
                }
            } else {
                ensure!(
                    existing.as_ref() == Some(&binding),
                    "instance belongs to another activity"
                );
                if matches!(
                    managed.instance.state(),
                    InstanceState::Stopped | InstanceState::Error(_)
                ) {
                    return Ok(OpsResponse {
                        ok: true,
                        instances: vec![status(managed).await?],
                        ..Default::default()
                    });
                }
            }
        }
        let mut response = OpsResponse {
            ok: true,
            ..Default::default()
        };
        let mut states = managed.instance.state_watch();
        let expected = match request.op {
            OpsOp::Start { .. } | OpsOp::StartLeague { .. } => {
                if !matches!(
                    managed.instance.state(),
                    InstanceState::Stopped | InstanceState::Error(_)
                ) {
                    return Err(crate::ops_extended::fault(
                        node::protocol::OpsErrorCode::InvalidState,
                        "instance is not stopped",
                    ));
                }
                managed.instance.start().await?;
                Some(InstanceState::Running)
            }
            OpsOp::Stop { .. } | OpsOp::StopLeague { .. } => {
                if managed.instance.state() != InstanceState::Running {
                    return Err(crate::ops_extended::fault(
                        node::protocol::OpsErrorCode::InvalidState,
                        "instance is not running",
                    ));
                }
                managed.instance.stop().await?;
                Some(InstanceState::Stopped)
            }
            OpsOp::Kill { .. } => {
                if managed.instance.state() != InstanceState::Running {
                    return Err(crate::ops_extended::fault(
                        node::protocol::OpsErrorCode::InvalidState,
                        "instance is not running",
                    ));
                }
                managed.instance.kill().await?;
                Some(InstanceState::Stopped)
            }
            OpsOp::Restart { .. } => {
                if managed.instance.state() != InstanceState::Running {
                    return Err(crate::ops_extended::fault(
                        node::protocol::OpsErrorCode::InvalidState,
                        "instance is not running",
                    ));
                }
                managed.instance.restart().await?;
                Some(InstanceState::Running)
            }
            OpsOp::Logs { .. } => {
                let mut logs = managed.instance.recent_output(LOG_LINES).await?.join("\n");
                if logs.len() > LOG_BYTES {
                    let mut boundary = logs.len() - LOG_BYTES;
                    while !logs.is_char_boundary(boundary) {
                        boundary += 1;
                    }
                    logs.drain(..boundary);
                }
                response.logs = Some(logs);
                None
            }
            _ => None,
        };
        if let Some(expected) = expected {
            timeout(OP_TIMEOUT, async {
                loop {
                    let state = states.borrow_and_update().clone();
                    if state == expected {
                        return Ok::<_, anyhow::Error>(());
                    }
                    if let InstanceState::Error(error) = state {
                        anyhow::bail!("instance operation failed: {error}");
                    }
                    states
                        .changed()
                        .await
                        .context("instance supervisor stopped")?;
                }
            })
            .await
            .map_err(|_| {
                crate::ops_extended::fault(
                    node::protocol::OpsErrorCode::Timeout,
                    "instance operation timed out",
                )
            })??;
        }
        response.instances.push(status(managed).await?);
        Ok(response)
    }
    pub async fn shutdown(&self) -> crate::Result<()> {
        self.shutdown_inner().await.map_err(crate::operation_error)
    }
    async fn shutdown_inner(&self) -> Result<()> {
        self.extended.shutdown().await?;
        let mut failure = None;
        for managed in self.instances.values() {
            if let Err(error) = shutdown_instance(&managed.instance).await {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}
pub(crate) async fn status(managed: &Managed) -> Result<OpsInstance> {
    let state = match managed.instance.state() {
        InstanceState::Stopped => OpsInstanceState::Stopped,
        InstanceState::Starting => OpsInstanceState::Starting,
        InstanceState::Running => OpsInstanceState::Running,
        InstanceState::Stopping => OpsInstanceState::Stopping,
        InstanceState::Busy => OpsInstanceState::Busy,
        InstanceState::Error(_) => OpsInstanceState::Error,
    };
    let ping = if state == OpsInstanceState::Running {
        minecraftd::minecraft::ping::ping_java_server(
            &managed.config.backend.to_string(),
            PING_TIMEOUT,
        )
        .await
        .ok()
    } else {
        None
    };
    Ok(OpsInstance {
        id: managed.config.id.clone(),
        kind: managed.config.server.server_type.clone(),
        state,
        players_online: ping.as_ref().map(|p| p.current_players).unwrap_or_default(),
        players_max: ping.as_ref().map(|p| p.max_players).unwrap_or_default(),
        version: ping.as_ref().map(|p| p.version.clone()).unwrap_or_default(),
        description: ping.map(|p| p.description),
    })
}

pub(crate) fn access(view: authority::trust::TrustView) -> node::AccessPolicy {
    node::AccessPolicy::TrustAny {
        view,
        requirements: [
            "manage", "read", "logs", "operate", "console", "backup", "restore",
        ]
        .into_iter()
        .map(|permission| node::protocol::TrustRequirement {
            clubs: Default::default(),
            permission: Some(permission.into()),
        })
        .collect(),
    }
}

fn authorize_operation(
    view: &authority::trust::TrustView,
    audience: node::PeerId,
    service: ServiceId,
    peer: node::PeerId,
    op: &OpsOp,
) -> Result<()> {
    let permission = match op {
        OpsOp::ListInstances {}
        | OpsOp::Status { .. }
        | OpsOp::Capabilities {}
        | OpsOp::Metrics { .. }
        | OpsOp::ListJobs { .. }
        | OpsOp::GetJob { .. }
        | OpsOp::ListBackups { .. } => "read",
        OpsOp::Logs { .. } | OpsOp::ListAudit { .. } => "logs",
        OpsOp::Start { .. }
        | OpsOp::StartLeague { .. }
        | OpsOp::StopLeague { .. }
        | OpsOp::Stop { .. }
        | OpsOp::Restart { .. }
        | OpsOp::Kill { .. } => "operate",
        OpsOp::Command { .. } => "console",
        OpsOp::CreateBackup { .. } | OpsOp::VerifyBackup { .. } | OpsOp::DeleteBackup { .. } => {
            "backup"
        }
        OpsOp::RestoreBackup { .. } => "restore",
    };
    for permission in ["manage", permission] {
        let requirement = node::protocol::TrustRequirement {
            clubs: Default::default(),
            permission: Some(permission.into()),
        };
        if view
            .authorize(
                &peer.to_string(),
                &audience.to_string(),
                &service.to_string(),
                &requirement,
            )
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(crate::ops_extended::fault(
        node::protocol::OpsErrorCode::PermissionDenied,
        format!("operation requires manage or {permission} permission"),
    ))
}

pub async fn serve(
    node: &Node,
    mut incoming: tokio::sync::mpsc::Receiver<node::IncomingSession>,
    service: ServiceId,
    fleet: Arc<Fleet>,
    view: authority::trust::TrustView,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            session = incoming.recv() => {
                let Some(mut session) = session else { break; };
                let fleet = fleet.clone();
                let view = view.clone();
                let audience = node.peer_id();
                tasks.spawn(async move {
                    timeout(OP_TIMEOUT, async {
                        let frame: JsonFrame = read_frame(&mut session.stream).await?;
                        ensure!(frame.sequence == 0 && frame.last, "invalid ops envelope");
                        let result = match serde_json::from_slice::<OpsRequest>(&frame.json) {
                            Ok(request) => match authorize_operation(&view, audience, service, session.peer, &request.op) {
                                Ok(()) => fleet.execute_tracked(request, &session.peer.to_string()).await,
                                Err(error) => Err(error),
                            }
                            Err(error) => Err(crate::ops_extended::fault(
                                node::protocol::OpsErrorCode::InvalidRequest,
                                error.to_string(),
                            )),
                        };
                        let response = result.unwrap_or_else(|error| OpsResponse {
                            ok: false,
                            error: Some(crate::ops_extended::error_response(&error)),
                            ..Default::default()
                        });
                        write_frame(&mut session.stream, &JsonFrame { json: serde_json::to_vec(&response)?, sequence: 0, last: true }).await?;
                        Ok::<_, anyhow::Error>(())
                    }).await?
                });
            }
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "ops task failed"); }
            }
        }
    }
    node.withdraw(service).await;
    tasks.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minecraftd::instance::server::ServerConfig;

    fn fixture(directory: &std::path::Path, command: &str) -> Result<(Arc<Fleet>, InstanceConfig)> {
        let instance = InstanceConfig {
            id: "test".into(),
            directory: directory.join("instance"),
            backend: "127.0.0.1:25565".parse()?,
            server: ServerConfig {
                start_command: command.into(),
                server_type: "minecraft/java".into(),
                ..Default::default()
            },
        };
        std::fs::create_dir_all(&instance.directory)?;
        let fleet = Arc::new(Fleet::new(Config {
            instances: vec![instance.clone()],
            state: directory.join("jobs.json"),
            audit: directory.join("audit.jsonl"),
            archives: minecraftd::archive::manager::ArchiveConfig {
                base_dir: directory.join("archives"),
                ..Default::default()
            },
        })?);
        Ok((fleet, instance))
    }

    async fn wait_job(fleet: &Arc<Fleet>, id: &str) -> Result<node::protocol::OpsJob> {
        timeout(Duration::from_secs(15), async {
            loop {
                let response = fleet
                    .execute(
                        OpsRequest {
                            op: OpsOp::GetJob { job: id.into() },
                        },
                        "test",
                    )
                    .await?;
                let job = response.job.context("job missing")?;
                if matches!(
                    job.state,
                    node::protocol::OpsJobState::Succeeded | node::protocol::OpsJobState::Failed
                ) {
                    return Ok(job);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }

    #[tokio::test]
    async fn failed_start_is_reported_and_unknown_instances_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = InstanceConfig {
            id: "test".into(),
            directory: directory.path().join("instance"),
            backend: "127.0.0.1:25565".parse()?,
            server: ServerConfig {
                start_command: "/nonexistent/federated-room-test".into(),
                server_type: "minecraft/java".into(),
                ..Default::default()
            },
        };
        std::fs::create_dir(&config.directory)?;
        assert!(
            Fleet::new(Config {
                instances: vec![config.clone(), config.clone()],
                state: directory.path().join("jobs.json"),
                audit: directory.path().join("audit.jsonl"),
                archives: minecraftd::archive::manager::ArchiveConfig {
                    base_dir: directory.path().join("archives"),
                    ..Default::default()
                },
            })
            .is_err()
        );
        let fleet = Arc::new(Fleet::new(Config {
            instances: vec![config],
            state: directory.path().join("jobs.json"),
            audit: directory.path().join("audit.jsonl"),
            archives: minecraftd::archive::manager::ArchiveConfig {
                base_dir: directory.path().join("archives"),
                ..Default::default()
            },
        })?);
        let list = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::ListInstances {},
                },
                "test",
            )
            .await?;
        assert!(list.ok);
        assert_eq!(list.instances.len(), 1);
        assert_eq!(list.instances[0].state, OpsInstanceState::Stopped);
        assert!(
            fleet
                .execute(
                    OpsRequest {
                        op: OpsOp::Status {
                            instance: "unknown".into()
                        }
                    },
                    "test"
                )
                .await
                .is_err()
        );
        assert!(
            fleet
                .execute(
                    OpsRequest {
                        op: OpsOp::Start {
                            instance: "test".into()
                        }
                    },
                    "test"
                )
                .await
                .is_err()
        );
        fleet.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn identity_session_returns_single_frame_success_and_business_errors() -> Result<()> {
        timeout(Duration::from_secs(30), async {
            use identity::Identity;
            use node::{NodeConfig, Service};

            let directory = tempfile::tempdir()?;
            let host_key = Identity::generate();
            let user = Identity::generate();
            let reader = Identity::generate();
            let mut identities = crate::test_identity::Identities::new(
                &[
                    (&host_key, "host", "club"),
                    (&user, "user", "club"),
                    (&reader, "reader", "club"),
                ],
                "host",
            );
            std::fs::create_dir(directory.path().join("instance"))?;
            let fleet = Arc::new(Fleet::new(Config {
                instances: vec![InstanceConfig {
                    id: "test".into(),
                    directory: directory.path().join("instance"),
                    backend: "127.0.0.1:25565".parse()?,
                    server: ServerConfig {
                        start_command: "/nonexistent/federated-room-network-test".into(),
                        ..Default::default()
                    },
                }],
                state: directory.path().join("jobs.json"),
                audit: directory.path().join("audit.jsonl"),
                archives: minecraftd::archive::manager::ArchiveConfig {
                    base_dir: directory.path().join("archives"),
                    ..Default::default()
                },
            })?);
            let mut host = Node::start(host_key.clone(), NodeConfig::default()).await?;
            let incoming = host.take_incoming()?;
            let service = ServiceId::new();
            identities.service(&host_key, &service.to_string(), "user", "manage");
            let root = identities.root("club");
            identities.append(
                node::protocol::TrustAction::GrantPermission {
                    id: "ops-reader".into(),
                    member: "reader".into(),
                    service: service.to_string(),
                    permission: "read".into(),
                },
                &[&root],
            );
            identities.log.mark_current()?;
            let view = identities.log.view(Duration::from_secs(60))?;
            host.publish(Service {
                id: service,
                name: "Operations fixture".into(),
                protocol: node::protocol::OPS_PROTOCOL.into(),
                metadata: vec![],
                access: access(view.clone()),
            })
            .await?;
            let client = Node::start(user, NodeConfig::default()).await?;
            client.dial(host.addresses()[0].clone()).await?;
            let mut tasks = JoinSet::new();
            let host = Arc::new(host);
            let serving = host.clone();
            let managed = fleet.clone();
            tasks.spawn(async move { serve(&serving, incoming, service, managed, view).await });
            for (json, ok) in [
                (r#"{"op":{"op":"list_instances"}}"#, true),
                (r#"{"op":{"op":"status","instance":"missing"}}"#, false),
                (r#"{"op":{"op":"start","instance":"test"}}"#, false),
                (r#"{"op":{"op":"list_instances","unexpected":true}}"#, false),
                (r#"{"op":{"op":"list_instances"}}"#, true),
            ] {
                let mut stream = client.open_service(host.peer_id(), service).await?;
                write_frame(
                    &mut stream,
                    &JsonFrame {
                        json: json.as_bytes().to_vec(),
                        sequence: 0,
                        last: true,
                    },
                )
                .await?;
                let frame: JsonFrame = read_frame(&mut stream).await?;
                assert_eq!(frame.sequence, 0);
                assert!(frame.last);
                let response: OpsResponse = serde_json::from_slice(&frame.json)?;
                assert_eq!(response.ok, ok);
                if ok {
                    assert_eq!(response.instances.len(), 1);
                    assert_eq!(response.instances[0].id, "test");
                } else {
                    assert!(
                        response
                            .error
                            .is_some_and(|error| !error.message.is_empty())
                    );
                }
            }
            let capabilities = client::ops::execute(
                &client,
                host.peer_id(),
                service,
                &OpsRequest {
                    op: OpsOp::Capabilities {},
                },
            )
            .await?;
            assert!(capabilities.ok && capabilities.capabilities.is_some());
            let missing = client::ops::execute(
                &client,
                host.peer_id(),
                service,
                &OpsRequest {
                    op: OpsOp::Status {
                        instance: "missing".into(),
                    },
                },
            )
            .await?;
            assert_eq!(
                missing.error.map(|error| error.code),
                Some(node::protocol::OpsErrorCode::NotFound)
            );
            let read_only = Node::start(reader, NodeConfig::default()).await?;
            read_only.dial(host.addresses()[0].clone()).await?;
            let listed = client::ops::execute(
                &read_only,
                host.peer_id(),
                service,
                &OpsRequest {
                    op: OpsOp::ListInstances {},
                },
            )
            .await?;
            assert!(listed.ok);
            let denied = client::ops::execute(
                &read_only,
                host.peer_id(),
                service,
                &OpsRequest {
                    op: OpsOp::Start {
                        instance: "test".into(),
                    },
                },
            )
            .await?;
            assert!(!denied.ok);
            assert_eq!(
                denied.error.map(|error| error.code),
                Some(node::protocol::OpsErrorCode::PermissionDenied)
            );
            read_only.shutdown().await?;
            tasks.shutdown().await;
            host.withdraw(service).await;
            fleet.shutdown().await?;
            client.shutdown().await?;
            Arc::try_unwrap(host)
                .map_err(|_| anyhow::anyhow!("operations task still owns host"))?
                .shutdown()
                .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }

    #[tokio::test]
    async fn capabilities_metrics_and_command_validation_are_network_ready() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (fleet, _) = fixture(directory.path(), "/nonexistent/ops-metrics")?;
        let capabilities = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::Capabilities {},
                },
                "test",
            )
            .await?;
        assert!(
            capabilities
                .capabilities
                .is_some_and(|value| value.persistent_jobs && value.backups)
        );
        let metrics = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::Metrics {
                        instance: Some("test".into()),
                    },
                },
                "test",
            )
            .await?;
        assert_eq!(metrics.metrics.len(), 1);
        assert_eq!(metrics.metrics[0].target, "test");
        assert_eq!(metrics.metrics[0].responsive, Some(false));
        assert_eq!(metrics.metrics[0].process_id, None);
        for command in ["stop\nreload", ""] {
            assert!(
                fleet
                    .execute(
                        OpsRequest {
                            op: OpsOp::Command {
                                instance: "test".into(),
                                command: command.into()
                            },
                        },
                        "test"
                    )
                    .await
                    .is_err()
            );
        }
        let audit = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::ListAudit {
                        offset: 0,
                        limit: Some(10),
                    },
                },
                "test",
            )
            .await?;
        assert_eq!(audit.audit.len(), 2);
        assert!(audit.audit.iter().all(|record| !record.success));
        fleet.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn backup_jobs_are_idempotent_verified_and_persistent() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (fleet, instance) = fixture(directory.path(), "/nonexistent/ops-backup")?;
        std::fs::create_dir(instance.directory.join("world"))?;
        std::fs::write(instance.directory.join("world/level.dat"), b"original")?;
        let request = OpsRequest {
            op: OpsOp::CreateBackup {
                instance: "test".into(),
                label: "before update".into(),
                idempotency_key: "backup-request-1".into(),
            },
        };
        let submitted = fleet.execute(request.clone(), "test").await?;
        let id = submitted.job.context("job not submitted")?.id;
        let duplicate = fleet.execute(request, "test").await?;
        assert_eq!(duplicate.job.context("duplicate job missing")?.id, id);
        let job = wait_job(&fleet, &id).await?;
        assert_eq!(
            job.state,
            node::protocol::OpsJobState::Succeeded,
            "{:?}",
            job.error
        );
        let backup = job.result_backup.context("backup result missing")?;
        assert_eq!(backup.label, "before update");
        let verify = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::VerifyBackup {
                        instance: "test".into(),
                        backup: backup.id.clone(),
                        idempotency_key: "verify-request-1".into(),
                    },
                },
                "test",
            )
            .await?
            .job
            .context("verify job missing")?;
        let verified = wait_job(&fleet, &verify.id).await?;
        assert_eq!(
            verified.state,
            node::protocol::OpsJobState::Succeeded,
            "{:?}",
            verified.error
        );
        assert_eq!(verified.verified, Some(true));
        let listed = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::ListBackups {
                        instance: "test".into(),
                        offset: 0,
                        limit: Some(10),
                    },
                },
                "test",
            )
            .await?;
        assert_eq!(listed.backups, vec![backup.clone()]);
        fleet.shutdown().await?;
        drop(fleet);

        let (reopened, _) = fixture(directory.path(), "/nonexistent/ops-backup")?;
        let persisted = reopened
            .execute(
                OpsRequest {
                    op: OpsOp::GetJob { job: id },
                },
                "test",
            )
            .await?;
        assert_eq!(
            persisted.job.context("persisted job missing")?.state,
            node::protocol::OpsJobState::Succeeded
        );
        let deleted = reopened
            .execute(
                OpsRequest {
                    op: OpsOp::DeleteBackup {
                        instance: "test".into(),
                        backup: backup.id,
                    },
                },
                "test",
            )
            .await?;
        assert!(deleted.ok);
        let empty = reopened
            .execute(
                OpsRequest {
                    op: OpsOp::ListBackups {
                        instance: "test".into(),
                        offset: 0,
                        limit: None,
                    },
                },
                "test",
            )
            .await?;
        assert!(empty.backups.is_empty());
        reopened.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn command_returns_only_new_process_output() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (fleet, _) = fixture(directory.path(), "sh -c 'cat'")?;
        fleet
            .execute(
                OpsRequest {
                    op: OpsOp::Start {
                        instance: "test".into(),
                    },
                },
                "test",
            )
            .await?;
        let response = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::Command {
                        instance: "test".into(),
                        command: "save-all".into(),
                    },
                },
                "test",
            )
            .await?;
        assert!(response.logs.is_some_and(|logs| logs.contains("save-all")));
        fleet.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn interrupted_jobs_reopen_as_failed() -> Result<()> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("jobs.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "jobs": [{
                    "id": "interrupted",
                    "kind": "create_backup",
                    "state": "running",
                    "actor": "test",
                    "instance": "test",
                    "created_ms": 1,
                    "updated_ms": 1,
                    "idempotency_key": "interrupted-request",
                    "request_digest": "a".repeat(64)
                }]
            }))?,
        )?;
        let (fleet, _) = fixture(directory.path(), "/nonexistent/ops-recovery")?;
        let response = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::GetJob {
                        job: "interrupted".into(),
                    },
                },
                "test",
            )
            .await?;
        let job = response.job.context("recovered job missing")?;
        assert_eq!(job.state, node::protocol::OpsJobState::Failed);
        assert_eq!(
            job.error.map(|error| error.message),
            Some("server restarted before the job completed".into())
        );
        fleet.shutdown().await?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_auto_restart_restarts_a_crashed_process() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let instance = InstanceConfig {
            id: "test".into(),
            directory: directory.path().join("instance"),
            backend: "127.0.0.1:25565".parse()?,
            server: ServerConfig {
                start_command: "sh -c 'echo attempt >> attempts; exit 1'".into(),
                auto_restart: true,
                auto_restart_max_times: 1,
                ..Default::default()
            },
        };
        std::fs::create_dir(&instance.directory)?;
        let service = instance.create()?;
        service.start().await?;
        timeout(Duration::from_secs(10), async {
            loop {
                let attempts = std::fs::read_to_string(instance.directory.join("attempts"))
                    .map(|value| value.lines().count())
                    .unwrap_or(0);
                if attempts >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        timeout(Duration::from_secs(5), async {
            while service.state() != InstanceState::Stopped {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        service.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn restore_replaces_data_and_keeps_a_safety_backup() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (fleet, instance) = fixture(directory.path(), "/nonexistent/ops-restore")?;
        let world = instance.directory.join("world");
        std::fs::create_dir(&world)?;
        std::fs::write(world.join("level.dat"), b"original")?;
        let create = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::CreateBackup {
                        instance: "test".into(),
                        label: "original world".into(),
                        idempotency_key: "restore-source".into(),
                    },
                },
                "test",
            )
            .await?
            .job
            .context("create job missing")?;
        let created = wait_job(&fleet, &create.id).await?;
        assert_eq!(
            created.state,
            node::protocol::OpsJobState::Succeeded,
            "{:?}",
            created.error
        );
        let backup = created.result_backup.context("source backup missing")?;
        std::fs::write(world.join("level.dat"), b"changed")?;
        let restore = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::RestoreBackup {
                        instance: "test".into(),
                        backup: backup.id,
                        idempotency_key: "restore-request".into(),
                    },
                },
                "test",
            )
            .await?
            .job
            .context("restore job missing")?;
        let restored = wait_job(&fleet, &restore.id).await?;
        assert_eq!(
            restored.state,
            node::protocol::OpsJobState::Succeeded,
            "{:?}",
            restored.error
        );
        assert!(restored.safety_backup.is_some());
        assert_eq!(std::fs::read(world.join("level.dat"))?, b"original");
        let backups = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::ListBackups {
                        instance: "test".into(),
                        offset: 0,
                        limit: Some(10),
                    },
                },
                "test",
            )
            .await?;
        assert_eq!(backups.backups.len(), 2);
        assert!(
            backups
                .backups
                .iter()
                .any(|backup| backup.label == "before restore")
        );
        fleet.shutdown().await?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_restored_start_rolls_back_and_restarts_the_original() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let (fleet, instance) = fixture(directory.path(), "./start.sh")?;
        let world = instance.directory.join("world");
        std::fs::create_dir(&world)?;
        std::fs::write(world.join("level.dat"), b"backup")?;
        let script = instance.directory.join("start.sh");
        std::fs::write(&script, b"#!/bin/sh\nexit 1\n")?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o644))?;
        let create = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::CreateBackup {
                        instance: "test".into(),
                        label: "unstartable restore".into(),
                        idempotency_key: "rollback-source".into(),
                    },
                },
                "test",
            )
            .await?
            .job
            .context("create job missing")?;
        let created = wait_job(&fleet, &create.id).await?;
        assert_eq!(
            created.state,
            node::protocol::OpsJobState::Succeeded,
            "{:?}",
            created.error
        );
        let backup = created.result_backup.context("source backup missing")?;
        std::fs::write(world.join("level.dat"), b"current")?;
        std::fs::write(&script, b"#!/bin/sh\nexec sleep 60\n")?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        fleet
            .execute(
                OpsRequest {
                    op: OpsOp::Start {
                        instance: "test".into(),
                    },
                },
                "test",
            )
            .await?;
        let restore = fleet
            .execute(
                OpsRequest {
                    op: OpsOp::RestoreBackup {
                        instance: "test".into(),
                        backup: backup.id,
                        idempotency_key: "rollback-restore".into(),
                    },
                },
                "test",
            )
            .await?
            .job
            .context("restore job missing")?;
        let restored = wait_job(&fleet, &restore.id).await?;
        assert_eq!(
            restored.state,
            node::protocol::OpsJobState::Failed,
            "{:?}",
            restored.error
        );
        assert_eq!(std::fs::read(world.join("level.dat"))?, b"current");
        timeout(Duration::from_secs(5), async {
            while fleet.instances["test"].instance.state() != InstanceState::Running {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        fleet.shutdown().await?;
        Ok(())
    }
}
