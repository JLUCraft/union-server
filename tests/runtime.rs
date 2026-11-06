use federated_server::runtime::{Application, Config, Host};
use identity::Identity;
use node::{Node, NodeConfig, ServiceId};
use serde_json::json;
use std::time::Duration;
const TEST_ROOT: &[u8] = include_bytes!("fixtures/founders.json");
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn configuration_requires_the_explicit_root_and_matching_digest() -> Result {
    let dir = tempfile::tempdir()?;
    let root = federated_server::bootstrap::parse_genesis(TEST_ROOT)?;
    let path = dir.path().join("node.json");
    let config = json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{"identity":{
        "log":"identity.jsonl","writer":true,"max_staleness_seconds":60
    }}});
    write(&path, &config)?;
    let missing = Config::load(&path, None)
        .err()
        .ok_or("missing root was accepted")?;
    assert!(
        missing
            .to_string()
            .contains("requires an explicit trust root")
    );
    let loaded = Config::load(&path, Some(&root))?;
    assert_eq!(
        loaded
            .services
            .identity
            .ok_or("missing identity")?
            .genesis_hash,
        federated_server::bootstrap::validate_genesis(&root)?
    );
    let mut other = root.clone();
    other.namespace.organization = "another-explicit-test-root".into();
    let mut mismatched = config;
    mismatched["services"]["identity"]["genesis_hash"] =
        federated_server::bootstrap::validate_genesis(&other)?.into();
    write(&path, &mismatched)?;
    assert!(Config::load(&path, Some(&root)).is_err());
    let mut invalid = root;
    invalid.founders.clear();
    assert!(Config::load(&path, Some(&invalid)).is_err());
    Ok(())
}

#[test]
fn embedded_genesis_file_cannot_replace_the_explicit_root() -> Result {
    let dir = tempfile::tempdir()?;
    let root = federated_server::bootstrap::parse_genesis(TEST_ROOT)?;
    Identity::generate().save_new(dir.path().join("node.key"))?;
    let mut other = root.clone();
    other.namespace.organization = "different-file-test-root".into();
    write(&dir.path().join("identity-genesis.json"), &other)?;
    let path = dir.path().join("node.json");
    write(
        &path,
        &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{"identity":{
            "genesis":"identity-genesis.json","log":"identity.jsonl","writer":true,"max_staleness_seconds":60
        }}}),
    )?;
    assert!(Config::load(&path, Some(&root)).is_err());
    assert!(!dir.path().join("identity.jsonl").exists());
    write(&dir.path().join("identity-genesis.json"), &root)?;
    Config::load(&path, Some(&root))?;
    Ok(())
}

fn write(path: &std::path::Path, value: &impl serde::Serialize) -> Result {
    std::fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
#[tokio::test]
async fn lightweight_node_needs_no_game_or_governance_files() -> Result {
    let dir = tempfile::tempdir()?;
    let key = Identity::generate();
    key.save_new(dir.path().join("node.key"))?;
    let config = dir.path().join("node.json");
    write(
        &config,
        &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{"directory":true,"relay":true}}),
    )?;
    let host = Host::start(Config::load(&config, None)?).await?;
    let status = host.status()?;
    assert_eq!(status.peer, key.peer_id().to_string());
    assert_eq!(status.services, ["directory", "relay"]);
    host.close().await?;
    assert!(!dir.path().join("journal").exists());
    assert!(!dir.path().join("server.properties").exists());
    Ok(())
}
#[test]
fn report_board_key_is_resolved_from_configuration_directory() -> Result {
    let directory = tempfile::tempdir()?;
    let base = directory.path().canonicalize()?;
    let path = base.join("node.json");
    let root = federated_server::bootstrap::parse_genesis(TEST_ROOT)?;
    for key in [
        std::path::PathBuf::from("worker.key"),
        base.join("worker.key"),
    ] {
        write(
            &path,
            &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{
                "identity":{"log":"identity.jsonl","writer":true,"max_staleness_seconds":60},
                "governance":{"genesis":"organization.json","journal":"office-journal"},
                "report_board":{"bind":"127.0.0.1:4237","key":key}
            }}),
        )?;
        let config = Config::load(&path, Some(&root))?;
        assert_eq!(
            config
                .services
                .report_board
                .ok_or("missing report board")?
                .key,
            base.join("worker.key")
        );
    }
    Ok(())
}
#[test]
fn configuration_rejects_unknown_fields_missing_governance_and_colliding_services() -> Result {
    for services in [
        json!({"gamez":true}),
        json!({"operations":{"service":ServiceId::new().to_string(),"issuers":[Identity::generate().peer_id().to_string()],"instances":[]}}),
        json!({"ai_worker":{"key":"k","providers":[],"grant":"g"}}),
    ] {
        let result = serde_json::from_value::<Config>(
            json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"unused"},"services":services}),
        );
        assert!(result.is_err() || result?.validate().is_err());
    }
    let id = ServiceId::new().to_string();
    let config: Config = serde_json::from_value(
        json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"unused"},"services":{
            "governance":{"genesis":"unused","journal":"unused"},
            "documents":{"service":id,"directory":"unused"},
            "operations":{"service":id,"instances":[]}
        }}),
    )?;
    assert!(config.validate().is_err());
    Ok(())
}
#[test]
fn mcp_configuration_resolves_only_relay_key_and_validates_target() -> Result {
    let dir = tempfile::tempdir()?;
    let peer = Identity::generate().peer_id().to_string();
    let path = dir.path().join("node.json");
    write(
        &path,
        &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{"mcp":{
            "bind":"127.0.0.1:9090",
            "relay_key":"relay.key",
            "operations":[{
                "name":"ops",
                "address":format!("/ip4/127.0.0.1/udp/40000/quic-v1/p2p/{peer}"),
                "peer":peer,
                "service":ServiceId::new().to_string()
            }],
            "principals":[{
                "name":"alice",
                "peer":Identity::generate().peer_id().to_string(),
                "operations":["ops"]
            }]
        }}}),
    )?;
    Identity::generate().save_new(dir.path().join("relay.key"))?;
    let config = Config::load(&path, None)?;
    let mcp = config
        .services
        .mcp
        .as_ref()
        .ok_or("MCP configuration missing")?;
    assert_eq!(mcp.relay_key, dir.path().join("relay.key"));
    assert_eq!(mcp.principals.len(), 1);
    config.validate()?;
    Ok(())
}

#[test]
fn application_configuration_has_one_genesis_and_journal() -> Result {
    let config: Config = serde_json::from_value(
        json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{
            "identity":{"log":"identity.jsonl","writer":true,"max_staleness_seconds":60,"genesis_hash":"0".repeat(64)},
            "governance":{"genesis":"application.json","journal":"application-journal"}
        }}),
    )?;
    config.validate()?;
    let governance = config
        .services
        .governance
        .ok_or("missing application governance")?;
    assert_eq!(
        governance.genesis,
        std::path::PathBuf::from("application.json")
    );
    assert_eq!(
        governance.journal,
        std::path::PathBuf::from("application-journal")
    );
    Ok(())
}
#[test]
fn relay_service_accepts_toggle_or_limit_overrides() -> Result {
    for services in [json!({}), json!({"relay":false}), json!({"relay":true})] {
        let config: Config = serde_json::from_value(
            json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"unused"},"services":services}),
        )?;
        config.validate()?;
    }
    let config: Config = serde_json::from_value(
        json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"unused"},"services":{
            "relay":{"max_circuits":64,"max_circuit_duration_seconds":7200}
        }}),
    )?;
    config.validate()?;
    for relay in [
        json!({"max_circuit":1}),
        json!({"max_circuits":0}),
        json!({"max_circuit_duration_seconds":0}),
        json!("yes"),
    ] {
        let result = serde_json::from_value::<Config>(
            json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"unused"},"services":{"relay":relay}}),
        );
        assert!(result.is_err() || result?.validate().is_err());
    }
    Ok(())
}
#[tokio::test]
async fn application_commands_share_one_journal_and_revocation() -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let host_key = Identity::generate(); host_key.save_new(dir.path().join("node.key"))?;
        let admin = Identity::generate();let member = Identity::generate();
        let operations = ServiceId::new();
        let (identity_config, cache, binding, root) = setup_identity(dir.path(), &admin, &host_key, Some((&member, operations)))?;
        let genesis = state::State::<Application>::new(binding)?;
        write(&dir.path().join("genesis.json"), &genesis)?;
        let pin = node::protocol::digest(&serde_json::to_vec(&genesis)?);
        let path = dir.path().join("node.json");
        write(&path, &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{
            "identity":identity_config,"governance":{"genesis":"genesis.json","journal":"journal"},
            "operations":{"service":operations.to_string(),"instances":[]}
        }}))?;
        let host = Host::start(Config::load(&path, Some(&root))?).await?;
        let status = host.status()?;
        let node = Node::start(member.clone(),NodeConfig::new(node::protocol::Namespace::jlucraft())).await?;
        node.dial(status.addresses[0].parse()?).await?;
        let services = node.list_services(host_key.peer_id()).await?;
        assert_eq!(services.len(),1);
        assert!(services.iter().any(|s| s.protocol == node::protocol::OPS_PROTOCOL));
        let cid = league::files::upload(&node,host_key.peer_id(),&pin,&member,league::files::Upload {
            branch:"main",path:"notes.txt",message:"initial",bytes:b"shared application"
        },&cache).await?;
        let snapshot = league::files::snapshot(&node,host_key.peer_id(),&pin).await?;
        assert_eq!(snapshot.domain.inner.files.read(&cid)?,b"shared application");
        let admin_node=Node::start(admin.clone(),NodeConfig::new(node::protocol::Namespace::jlucraft())).await?;
        admin_node.dial(status.addresses[0].parse()?).await?;
        let initial_revision = snapshot.revision;
        let now = authority::journal::now_ms()?;
        let activity = state::governance::Action::<Application>::Domain(flows::FlowAction::Inner(league::events::EventAction::Create {
            id: "activity".into(), title: "Shared organization activity".into(), brief_hash: cid.to_string(),
            window: league::events::Window { opens_ms: now, closes_ms: now + 60_000, starts_ms: now + 120_000 },
        }));
        let created = client::trust::execute::<Application>(&admin_node,host_key.peer_id(),&pin,&admin,&cache,activity,client::journal::PROTOCOL).await?.state.ok_or("missing activity state")?;
        assert_eq!(created.revision, initial_revision + 1);
        let competition = league::application::competition(league::LeagueAction::CreateLeague {
            league: "competition".into(), rules: Default::default(), host: host_key.peer_id().to_string(), scorer: member.peer_id().to_string(),
        });
        let combined = client::trust::execute::<Application>(&node,host_key.peer_id(),&pin,&member,&cache,competition,client::journal::PROTOCOL).await?.state.ok_or("missing combined state")?;
        assert_eq!(combined.revision, initial_revision + 2);
        assert!(combined.domain.events.contains_key("activity"));
        assert!(combined.domain.leagues.contains_key("competition"));
        let response = client::ops::execute(&node,host_key.peer_id(),operations,&node::protocol::OpsRequest { delegation: None,op:node::protocol::OpsOp::ListInstances{}}).await?;
        assert!(response.ok && response.instances.is_empty());
        let mut stream=node.open_service(host_key.peer_id(),operations).await?;
        let mut record=cache.state().draft(node::protocol::TrustAction::RevokeDevice{member:"alice".into(),device:member.peer_id().to_string()});
        client::trust::sign_with_namespace(&mut record,&admin, &node::protocol::Namespace::jlucraft())?;
        let response=client::trust::request(&admin_node,host_key.peer_id(),node::protocol::TrustRequest::Append{record}).await?;
        assert!(response.error.is_none(),"{:?}",response.error);
        assert!(node.open_service(host_key.peer_id(),operations).await.is_err());
        assert!(league::files::snapshot(&node,host_key.peer_id(),&pin).await.is_err());
        assert!(tokio::time::timeout(Duration::from_secs(3),node::protocol::read_frame::<node::protocol::JsonFrame>(&mut stream)).await?.is_err());
        admin_node.shutdown().await?;
        node.shutdown().await?;
        host.close().await?;
        let replay = authority::journal::Journal::<Application>::open_with_namespace(dir.path().join("journal"),genesis, node::protocol::Namespace::jlucraft())?;
        assert_eq!(replay.state().domain.inner.files.read(&cid)?,b"shared application");
        assert!(replay.state().domain.events.contains_key("activity"));
        assert!(replay.state().domain.leagues.contains_key("competition"));
        Ok::<_,Box<dyn std::error::Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn failed_start_and_dropped_host_release_governance_ownership() -> Result {
    let dir = tempfile::tempdir()?;
    let identity = Identity::generate();
    identity.save_new(dir.path().join("node.key"))?;
    let (identity_config, _cache, binding, root) =
        setup_identity(dir.path(), &identity, &identity, None)?;
    let genesis = state::State::<Application>::new(binding)?;
    write(&dir.path().join("genesis.json"), &genesis)?;
    let path = dir.path().join("node.json");
    let mut value = json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{
        "identity":identity_config,"governance":{"genesis":"genesis.json","journal":"journal"},
        "ai_worker":{"key":"node.key","providers":[{"id":"fixture","protocol":"chat_completions","url":"invalid-url","models":["test"],"context_tokens":128}]}
    }});
    write(&path, &value)?;
    assert!(
        Host::start(Config::load(&path, Some(&root))?)
            .await
            .is_err()
    );
    drop(authority::journal::Journal::open_with_namespace(
        dir.path().join("journal"),
        genesis.clone(),
        node::protocol::Namespace::jlucraft(),
    )?);
    value["services"]
        .as_object_mut()
        .ok_or("services object")?
        .remove("ai_worker");
    write(&path, &value)?;
    let host = Host::start(Config::load(&path, Some(&root))?).await?;
    drop(host);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if authority::journal::Journal::open_with_namespace(
                dir.path().join("journal"),
                genesis.clone(),
                node::protocol::Namespace::jlucraft(),
            )
            .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn setup_identity(
    dir: &std::path::Path,
    admin: &Identity,
    host: &Identity,
    member: Option<(&Identity, ServiceId)>,
) -> Result<(
    serde_json::Value,
    client::trust::TrustLog,
    node::protocol::TrustBusinessBinding,
    node::protocol::TrustGenesis,
)> {
    use node::protocol::{TrustAction as A, TrustBusinessBinding, TrustFounder, TrustGenesis};
    let genesis = TrustGenesis {
        namespace: node::protocol::Namespace::jlucraft(),
        quorum: 1,
        founders: vec![TrustFounder {
            member: "chair".into(),
            club: "school".into(),
            public_key: admin.public_key().encode_protobuf(),
        }],
    };
    let pin = client::trust::TrustState::genesis_digest(&genesis)?;
    write(&dir.join("identity-genesis.json"), &genesis)?;
    let mut log = client::trust::TrustLog::open_with_namespace(
        &dir.join("identity.jsonl"),
        &genesis,
        &pin,
        node::protocol::Namespace::jlucraft(),
    )?;
    let mut actions = vec![
        A::RegisterService {
            service: "application".into(),
            audience: host.peer_id().to_string(),
            club: "school".into(),
        },
        A::GrantPermission {
            id: "chair-application".into(),
            member: "chair".into(),
            service: "application".into(),
            permission: "admin".into(),
        },
    ];
    if let Some((member, operations)) = member {
        actions.extend([
            A::ConfirmMember {
                member: "alice".into(),
                club: "school".into(),
                device: Some(member.peer_id().to_string()),
                evidence: "manual".into(),
                verifier: None,
            },
            A::RegisterService {
                service: operations.to_string(),
                audience: host.peer_id().to_string(),
                club: "school".into(),
            },
            A::GrantPermission {
                id: "application-admin".into(),
                member: "alice".into(),
                service: "application".into(),
                permission: "admin".into(),
            },
            A::GrantPermission {
                id: "ops-manage".into(),
                member: "alice".into(),
                service: operations.to_string(),
                permission: "manage".into(),
            },
        ]);
    }
    for action in actions {
        let mut record = log.state().draft(action);
        for key in [Some(admin), Some(host), member.map(|m| m.0)]
            .into_iter()
            .flatten()
        {
            if !record
                .signatures
                .iter()
                .any(|s| s.public_key == key.public_key().encode_protobuf())
            {
                client::trust::sign_with_namespace(
                    &mut record,
                    key,
                    &node::protocol::Namespace::jlucraft(),
                )?;
            }
        }
        log.append(record)?;
    }
    let mut cache = client::trust::TrustLog::open_with_namespace(
        &dir.join("cache.jsonl"),
        &genesis,
        &pin,
        node::protocol::Namespace::jlucraft(),
    )?;
    for record in log.history_since(None)?.records {
        cache.append(record)?;
    }
    drop(log);
    Ok((
        json!({"genesis":"identity-genesis.json","genesis_hash":pin,"log":"identity.jsonl","writer":true,"max_staleness_seconds":60}),
        cache,
        TrustBusinessBinding {
            genesis: pin,
            namespace: "application".into(),
            audience: host.peer_id().to_string(),
            service: "application".into(),
            club: "school".into(),
        },
        genesis,
    ))
}

#[tokio::test]
async fn document_terminal_download_checks_hash_and_live_read_permission() -> Result {
    use node::protocol::{TrustAction, TrustRequest};
    let dir = tempfile::tempdir()?;
    let host_key = Identity::generate();
    let admin = Identity::generate();
    let reader = Identity::generate();
    host_key.save_new(dir.path().join("node.key"))?;
    let documents = ServiceId::new();
    let (identity_config, mut cache, _, root) =
        setup_identity(dir.path(), &admin, &host_key, Some((&reader, documents)))?;
    let source = dir.path().join("source.txt");
    std::fs::write(&source, b"verified terminal document")?;
    let collection = dir.path().join("documents");
    let hash = events::documents::store(&collection, &source)?;
    let path = dir.path().join("node.json");
    write(
        &path,
        &json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{"identity":identity_config,"documents":{"service":documents.to_string(),"directory":"documents"}}}),
    )?;
    let host = Host::start(Config::load(&path, Some(&root))?).await?;
    let status = host.status()?;
    let input = || client::documents::Input {
        namespace: node::protocol::Namespace::jlucraft(),
        address: status.addresses[0].clone(),
        peer: status.peer.clone(),
        service: documents.to_string(),
        hash: hash.clone(),
    };
    // Existing manage permission is intentionally insufficient for a document read.
    assert!(
        client::documents::fetch(reader.clone(), input())
            .await
            .is_err()
    );
    let node = Node::start(
        admin.clone(),
        NodeConfig::new(node::protocol::Namespace::jlucraft()),
    )
    .await?;
    node.dial(status.addresses[0].parse()?).await?;
    let mut grant = cache.state().draft(TrustAction::GrantPermission {
        id: "doc-read".into(),
        member: "alice".into(),
        service: documents.to_string(),
        permission: "read".into(),
    });
    client::trust::sign_with_namespace(&mut grant, &admin, &node::protocol::Namespace::jlucraft())?;
    let response = client::trust::request(
        &node,
        host_key.peer_id(),
        TrustRequest::Append {
            record: grant.clone(),
        },
    )
    .await?;
    assert!(response.error.is_none());
    cache.append(grant)?;
    assert_eq!(
        client::documents::fetch(reader.clone(), input()).await?,
        b"verified terminal document"
    );
    std::fs::write(collection.join(&hash), b"tampered")?;
    assert!(
        client::documents::fetch(reader.clone(), input())
            .await
            .is_err()
    );
    std::fs::write(collection.join(&hash), b"verified terminal document")?;
    let mut revoke = cache.state().draft(TrustAction::RevokePermission {
        id: "doc-read".into(),
    });
    client::trust::sign_with_namespace(
        &mut revoke,
        &admin,
        &node::protocol::Namespace::jlucraft(),
    )?;
    assert!(
        client::trust::request(
            &node,
            host_key.peer_id(),
            TrustRequest::Append { record: revoke }
        )
        .await?
        .error
        .is_none()
    );
    assert!(client::documents::fetch(reader, input()).await.is_err());
    node.shutdown().await?;
    host.close().await?;
    Ok(())
}

#[test]
fn namespace_configuration_requires_explicit_namespace_and_rejects_invalid_components() -> Result {
    let baseline = json!({"node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"}, "services":{"directory":true}});
    let mut missing = baseline.clone();
    missing["node"].as_object_mut().unwrap().remove("namespace");
    let error = serde_json::from_value::<Config>(missing)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("missing field `namespace`"), "{error}");
    let default: Config = serde_json::from_value(baseline.clone())?;
    assert_eq!(
        default.node.namespace,
        node::protocol::Namespace::jlucraft()
    );
    default.validate()?;
    let mut custom = baseline;
    custom["node"]["namespace"] = json!({"organization":"acme", "version":2});
    let config: Config = serde_json::from_value(custom.clone())?;
    config.validate()?;
    assert_eq!(config.node.namespace.node_protocol(), "/acme/union/2");
    let dir = tempfile::tempdir()?;
    let root = federated_server::bootstrap::parse_genesis(TEST_ROOT)?;
    let path = dir.path().join("node.json");
    let mut upgrade = json!({"node":{"key":"node.key","namespace":{"organization":"jlucraft","wire_version":2}},"services":{"identity":{"log":"identity.jsonl","writer":true,"max_staleness_seconds":60}}});
    write(&path, &upgrade)?;
    let loaded = Config::load(&path, Some(&root))?;
    assert_eq!(loaded.node.namespace.wire_version, 2);
    assert_eq!(
        loaded.services.identity.unwrap().genesis_hash,
        federated_server::bootstrap::validate_genesis(&root)?
    );
    for namespace in [
        json!({"organization":"other","wire_version":2}),
        json!({"organization":"jlucraft","wire_version":2,"signing_version":2}),
    ] {
        upgrade["node"]["namespace"] = namespace;
        write(&path, &upgrade)?;
        assert!(
            Config::load(&path, Some(&root))
                .err()
                .unwrap()
                .to_string()
                .contains("signing domain does not match")
        );
    }
    for invalid in [
        json!({"organization":"a/b", "version":2}),
        json!({"organization":"acme", "version":0}),
    ] {
        custom["node"]["namespace"] = invalid;
        assert!(
            serde_json::from_value::<Config>(custom.clone())?
                .validate()
                .is_err()
        );
    }
    Ok(())
}
