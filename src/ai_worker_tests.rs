use super::*;
use crate::runtime::Application;
type F = flows::FlowAction<league::events::EventsDomain>;
use authority::journal::Journal;
use client::protocol::Privacy;
use node::{Node, NodeConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn unified_identity_drives_local_provider_and_paid_worker() -> Result<()> {
    automatic_flow(false, None).await
}
#[cfg(feature = "server")]
#[tokio::test]
async fn replicated_office_runs_automatic_worker_and_replays_identity_witnesses() -> Result<()> {
    automatic_flow(true, None).await
}
#[tokio::test]
async fn automatic_review_applies_decisions_and_pauses_on_invalid_output() -> Result<()> {
    for decision in [
        "approve",
        "changes_requested",
        "reject",
        "invalid",
        "timeout",
    ] {
        automatic_flow(false, Some(decision)).await?;
    }
    Ok(())
}
async fn automatic_flow(replicated: bool, decision: Option<&'static str>) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let dir=tempfile::tempdir()?;
        let admin=Identity::generate(); let worker=Identity::generate(); let human=Identity::generate();
        let now=now_ms()?;
        let mut genesis;
        let template=flows::Template{name:"summarize then review".into(),payload_kinds:[if decision.is_some() {"events.approve".into()} else {"events.create".into()}].into(),stages:vec![flows::Stage{name:"summary".into(),approver:flows::Approver::Ai{mode:if decision.is_some() {flows::AiMode::Review} else {flows::AiMode::Generate},worker:"worker".into(),model:"local".into(),purpose:"events.summary".into(),privacy:Privacy::Sensitive,max_tokens:32},timeout_ms:if decision==Some("timeout") {Some(2000)} else {None},on_timeout:flows::TimeoutPolicy::Reject}]};
        let listener=TcpListener::bind("127.0.0.1:0").await?;
        let url=format!("http://{}/v1/chat/completions",listener.local_addr()?);
        let calls=Arc::new(AtomicUsize::new(0));let count=calls.clone();
        let provider=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();
            let mut header=Vec::new();
            while !header.ends_with(b"\r\n\r\n") {header.push(socket.read_u8().await.unwrap());assert!(header.len()<16384);}
            let header=String::from_utf8(header).unwrap();
            let length:usize=header.lines().find_map(|line|line.to_lowercase().strip_prefix("content-length:").map(|n|n.trim().parse().unwrap())).unwrap();
            let mut body=vec![0;length];socket.read_exact(&mut body).await.unwrap();
            let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
            assert_eq!(request["messages"][0]["role"],"system");
            assert_eq!(request["messages"][1]["role"],"user");
            let context:serde_json::Value=serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
            assert_eq!(context["material"],"meeting notes");
            assert_eq!(context["task"],"events.summary");
            assert_eq!(context["mode"],if decision.is_some() {"review"} else {"generate"});
            count.fetch_add(1,Ordering::SeqCst);
            if decision==Some("timeout") {tokio::time::sleep(std::time::Duration::from_secs(3)).await;return;}
            let content=match decision {
                None => "summary result".to_owned(),
                Some("invalid") => "looks good".to_owned(),
                Some(decision) => serde_json::json!({"decision":decision,"summary":"Review complete","issues":["Verify consent"]}).to_string(),
            };
            let delta=serde_json::json!({"choices":[{"index":0,"delta":{"content":content},"finish_reason":null}]}).to_string();
            let body=format!("data: {delta}\n\ndata: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\ndata: {{\"choices\":[],\"usage\":{{\"prompt_tokens\":8,\"completion_tokens\":2,\"total_tokens\":10}}}}\n\ndata: [DONE]\n\n");
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
        });
        let host_key=Identity::generate();
        let identity_genesis=node::protocol::TrustGenesis {namespace: node::protocol::Namespace::builtin(),quorum:1,founders:vec![node::protocol::TrustFounder {member:"chair".into(),club:"school".into(),public_key:admin.public_key().encode_protobuf()}]};
        let identity_pin=client::trust::TrustState::genesis_digest(&identity_genesis)?;
        {
            use node::protocol::TrustAction as T;
            let mut log=client::trust::TrustLog::open_with_namespace(&dir.path().join("identity.jsonl"),&identity_genesis,&identity_pin, node::protocol::Namespace::builtin())?;
            for action in [
                T::ConfirmMember {member:"worker".into(),club:"school".into(),device:Some(worker.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::ConfirmMember {member:"human".into(),club:"school".into(),device:Some(human.peer_id().to_string()),evidence:"manual".into(),verifier:None},
                T::RegisterService {service:"application".into(),audience:host_key.peer_id().to_string(),club:"school".into()},
                T::GrantPermission {id:"worker-office".into(),member:"worker".into(),service:"application".into(),permission:"write".into()},
                T::GrantPermission {id:"human-office".into(),member:"human".into(),service:"application".into(),permission:"admin".into()},
            ] {
                let mut record=log.state().draft(action);
                for key in [&admin,&worker,&human,&host_key] {client::trust::sign_with_namespace(&mut record,key, &node::protocol::Namespace::builtin())?;}
                log.append(record)?;
            }
            genesis=state::State::<Application>::new(node::protocol::TrustBusinessBinding {genesis:identity_pin.clone(),namespace:"application".into(),service:"application".into(),audience:host_key.peer_id().to_string(),club:"school".into()})?;
            std::fs::write(dir.path().join("identity-genesis.json"),serde_json::to_vec(&identity_genesis)?)?;
        }

        worker.save_new(dir.path().join("worker.key"))?;
        host_key.save_new(dir.path().join("node.key"))?;
        let mut config=serde_json::json!({
            "node":{"namespace":{"organization":"jlucraft","version":1},"key":"node.key"},"services":{
                "governance":{"genesis":"genesis.json","journal":"office"},
                "ai_worker":{"key":"worker.key","providers":[{"id":"fixture","protocol":"chat_completions","url":url,"models":["local"],"context_tokens":4096}]}
            }
        });
        {
            config["services"]["identity"]=serde_json::json!({"genesis":"identity-genesis.json","genesis_hash":identity_pin,"log":"identity.jsonl","writer":true,"source":null,"max_staleness_seconds":60});
        }
        #[cfg(feature = "server")]
        if replicated {
            let socket=std::net::TcpListener::bind("127.0.0.1:0")?;
            let port=socket.local_addr()?.port(); drop(socket);
            let address=format!("/ip4/127.0.0.1/tcp/{port}");
            let peers=std::collections::BTreeMap::from([(1, authority::consensus::Peer{peer:host_key.peer_id().to_string(),addresses:vec![format!("{address}/p2p/{}",host_key.peer_id())]})]);
            genesis=authority::consensus::Cluster::genesis(genesis,&peers)?;
            config["node"]["listen"]=serde_json::json!([address]);
            config["services"]["governance"]["replication"]=serde_json::json!({"id":1,"initialize":true,"peers":peers});
        }
        #[cfg(not(feature = "server"))]
        assert!(!replicated);
        genesis.domain.ai_pricing.insert("local".into(),flows::ai::AiPricing {base_points:1,input_points_per_1k:1,output_points_per_1k:1,max_input_tokens:1024,settlement:flows::ai::Settlement::Burn});
        genesis.domain.inner.organization.points.insert("school".into(),[("human".into(),1000)].into());
        std::fs::write(dir.path().join("genesis.json"),serde_json::to_vec(&genesis)?)?;
        let hash=node::protocol::digest(&serde_json::to_vec(&genesis)?);
        let config_path=dir.path().join("node.json");
        std::fs::write(&config_path,serde_json::to_vec(&config)?)?;
        let host=crate::runtime::Host::start(crate::runtime::Config::load(&config_path,Some(&identity_genesis))?).await?;
        let client_node=Node::start(human.clone(),NodeConfig::new(node::protocol::Namespace::builtin())).await?;
        client_node.dial(host.status()?.addresses[0].parse()?).await?;
        let cache={
            let log=Mutex::new(client::trust::TrustLog::open_with_namespace(&dir.path().join("client.jsonl"),&identity_genesis,&identity_pin, node::protocol::Namespace::builtin())?);
            authority::trust::synchronize(&client_node,host_key.peer_id(),&log).await?;log.into_inner()
        };
        while league::files::snapshot(&client_node,host_key.peer_id(),&hash).await.is_err() {tokio::time::sleep(std::time::Duration::from_millis(50)).await;}
        let install=state::governance::Action::Domain(F::InstallTemplate{id:"summary".into(),template});
        assert!(genesis.clone().apply(&worker.peer_id().to_string(),0,now,install.clone(),cache.state()).is_err());
        let installed=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,install,client::journal::PROTOCOL).await?;
        assert!(installed.error.is_none(),"{:?}",installed.error);
        let roles=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::SetMemberRoles{member:"human".into(),roles:["president".into()].into()},client::journal::PROTOCOL).await?;
        assert!(roles.error.is_none());
        let input=league::files::upload(&client_node,host_key.peer_id(),&hash,&human,league::files::Upload{branch:"main",path:"notes.txt",message:"meeting input",bytes:b"meeting notes"},&cache).await?;
        let snapshot=league::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
        let mut updates=authority::events::subscribe(&client_node,host_key.peer_id(),snapshot.revision,authority::events::PROTOCOL).await?;
        let create=league::events::EventAction::Create{id:"event".into(),title:"meeting".into(),brief_hash:input.to_string(),window:events::Window{opens_ms:now+60000,closes_ms:now+120000,starts_ms:now+180000}};
        let payload=if decision.is_some() {
            for action in [create,league::events::EventAction::Submit{id:"event".into()}] {
                let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::Domain(F::Inner(action)),client::journal::PROTOCOL).await?;
                assert!(reply.error.is_none());
            }
            league::events::EventAction::Approve{id:"event".into(),epoch:1,co_organizers:Default::default()}
        } else {create};
        let action=state::governance::Action::Domain(F::Start{ max_points: 1_000_000,id:"flow".into(),template:"summary".into(),input:Some(input.clone()),payload});
        let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,action,client::journal::PROTOCOL).await?;
        assert!(reply.error.is_none(),"{:?}",reply.error);
        let mut state=loop {
            let snapshot=league::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
            let flow=&snapshot.domain.flows["flow"];
            let expected=match decision {Some("reject" | "timeout")=>flows::Status::Rejected,Some("changes_requested")=>flows::Status::ChangesRequested,Some("invalid" | "approve")=>flows::Status::Active,_=>flows::Status::Approved};
            if flow.status==expected && flow.records[0].ai_runs.last().is_some_and(|r|r.output.is_some() || r.error.is_some()) {break snapshot;}
            authority::events::next(&mut updates).await?;
        };
        let run=&state.domain.flows["flow"].records[0].ai_runs[0];
        assert_eq!(state.domain.flows["flow"].records[0].escrowed_points,0);
        assert_eq!(state.domain.inner.organization.points["school"]["human"],if matches!(decision,Some("invalid"|"timeout")) {1000} else {998});

        if matches!(decision,Some("invalid" | "timeout")) {assert!(run.output.is_none());assert!(run.error.is_some());}
        else if decision.is_some() {assert!(run.review.is_some());}
        else {assert_eq!(state.domain.inner.files.read(run.output.as_ref().unwrap())?,b"summary result");}
        if decision==Some("approve") {
            let flow=&state.domain.flows["flow"];
            assert_eq!(flow.current,1);
            assert_eq!(state.domain.inner.events["event"].phase,league::events::Phase::Review);
            assert!(flow.deadline_ms.is_none());
            assert!(matches!(flows::template_for(&state.domain.flow_templates,flow)?.stages[1].approver,flows::Approver::ClubPresidents{..}));
            let worker_node=Node::start(worker.clone(),NodeConfig::new(node::protocol::Namespace::builtin())).await?;
            worker_node.dial(host.status()?.addresses[0].parse()?).await?;
            let denied=client::trust::execute::<Application>(&worker_node,host_key.peer_id(),&hash,&worker,&cache,state::governance::Action::Domain(F::Approve{instance:"flow".into(),comment_hash:"a".repeat(64)}),client::journal::PROTOCOL).await?;
            assert!(denied.error.is_some());
            worker_node.shutdown().await?;
            for action in [F::Approve{instance:"flow".into(),comment_hash:"a".repeat(64)},F::Execute{instance:"flow".into()}] {
                let reply=client::trust::execute::<Application>(&client_node,host_key.peer_id(),&hash,&human,&cache,state::governance::Action::Domain(action),client::journal::PROTOCOL).await?;
                assert!(reply.error.is_none(),"{:?}",reply.error);
            }
            state=league::files::snapshot(&client_node,host_key.peer_id(),&hash).await?;
            assert_eq!(state.domain.inner.events["event"].phase,league::events::Phase::Approved);
        }
        assert_eq!(calls.load(Ordering::SeqCst),1);
        provider.await?;
        drop(updates);
        client_node.shutdown().await?;
        host.close().await?;
        if !replicated {
            let replay=Journal::<Application>::open_with_namespace(dir.path().join("office"),genesis.clone(), node::protocol::Namespace::builtin())?;
            assert_eq!(replay.state(),&state);
        }
        #[cfg(feature = "server")]
        if replicated {
            let replay=authority::consensus::Store::open_with_namespace(&dir.path().join("office"),genesis, node::protocol::Namespace::builtin())?;
            assert_eq!(replay.state().await,state);
        }
        assert_eq!(calls.load(Ordering::SeqCst),1);
        Ok::<_,anyhow::Error>(())
    }).await?
}

// An office-only domain: no competitions, game resources or player points.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OfficeDomain;
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct OfficeState {
    files: events::office::files::FileStore,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum OfficeAction {
    PutBlock(node::protocol::IpldBlock),
    Review(node::protocol::Cid),
}
impl state::Domain for OfficeDomain {
    type State = OfficeState;
    type Action = OfficeAction;

    fn transition(
        state: &mut Self::State,
        _: &state::Context<'_>,
        action: Self::Action,
    ) -> node::Result<()> {
        match action {
            OfficeAction::PutBlock(block) => state.files.put(block),
            OfficeAction::Review(_) => Ok(()),
        }
    }
}
impl flows::Workflow for OfficeDomain {
    fn artifact(state: &Self::State, cid: &str) -> node::Result<Vec<u8>> {
        state.files.read(&cid.parse()?)
    }

    fn review_artifact(_: &Self::State, action: &Self::Action) -> node::Result<String> {
        match action {
            OfficeAction::Review(cid) => Ok(cid.to_string()),
            _ => Err(node::Error::Denied),
        }
    }

    fn workflow_input(state: &Self::State, action: &Self::Action) -> node::Result<Vec<u8>> {
        Self::artifact(state, &Self::review_artifact(state, action)?)
    }

    fn workflow_worker(_: &Self::State, _: &Self::Action) -> Option<String> {
        Some("worker".into())
    }
}
impl AiDomain for OfficeDomain {
    fn files(state: &Self::State) -> &events::office::files::FileStore {
        &state.files
    }

    fn put_block(block: node::protocol::IpldBlock) -> Self::Action {
        OfficeAction::PutBlock(block)
    }
}

#[tokio::test]
async fn office_domain_registers_worker_and_commits_file_versions() -> Result<()> {
    type Office = flows::Flows<OfficeDomain>;
    let dir = tempfile::tempdir()?;
    let worker = Identity::generate();
    let identities =
        crate::test_identity::Identities::new(&[(&worker, "worker", "school")], "worker");
    let genesis = identities.genesis::<Office>();
    let authority = Authority::Local {
        journal: Arc::new(Mutex::new(Journal::open_with_namespace(
            dir.path().join("office"),
            genesis,
            node::protocol::Namespace::builtin(),
        )?)),
        view: identities.log.view(std::time::Duration::from_secs(60))?,
        log: Arc::new(Mutex::new(identities.log)),
    };
    let files = OfficeState::default();
    let (input, blocks) = OfficeDomain::files(&files).version(None, b"office notes")?;
    for block in blocks {
        apply(
            &authority,
            &worker,
            flows::FlowAction::Inner(OfficeDomain::put_block(block)),
        )
        .await?;
    }
    let snapshot = authority.state(worker.peer_id()).await?;
    let (output, blocks) = OfficeDomain::files(&snapshot.domain.inner)
        .version(Some(input.clone()), b"office summary")?;
    for block in blocks {
        apply(
            &authority,
            &worker,
            flows::FlowAction::Inner(OfficeDomain::put_block(block)),
        )
        .await?;
    }
    let snapshot = authority.state(worker.peer_id()).await?;
    let files = OfficeDomain::files(&snapshot.domain.inner);
    assert_eq!(files.read(&input)?, b"office notes");
    assert_eq!(files.read(&output)?, b"office summary");

    let prepared = Prepared {
        identity: worker.clone(),
        providers: llm_gateway::Gateway::new(llm_gateway::Config {
            providers: vec![serde_json::from_value(serde_json::json!({
                "id":"fixture", "protocol":"chat_completions", "url":"http://127.0.0.1:1",
                "models":["local"], "context_tokens":4096
            }))?],
            concurrency: 1,
        })?,
    };
    let mut updates = authority.watch().await;
    let task = tokio::spawn(serve(authority.clone(), prepared));
    let registered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let snapshot = authority.state(worker.peer_id()).await?;
            if let Some(worker) = snapshot.domain.ai_workers.get("worker") {
                assert!(worker.active);
                assert_eq!(worker.models, ["local".into()].into());
                return Ok::<_, anyhow::Error>(());
            }
            updates.changed().await?;
        }
    })
    .await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    registered??;
    Ok(())
}

#[test]
fn office_domain_review_checks_canonical_input_and_cancellation() -> Result<()> {
    let worker = Identity::generate();
    let identities =
        crate::test_identity::Identities::new(&[(&worker, "worker", "school")], "worker");
    let mut snapshot = identities.genesis::<flows::Flows<OfficeDomain>>();
    let view = identities.log.view(std::time::Duration::from_secs(60))?;
    let (input, blocks) = snapshot
        .domain
        .inner
        .files
        .version(None, b"review material")?;
    for block in blocks {
        snapshot.domain.inner.files.put(block)?;
    }
    let job = flows::AiJob {
        mode: flows::AiMode::Review,
        instance: "review".into(),
        job: "job".into(),
        attempt: 0,
        input: input.clone(),
        worker: "worker".into(),
        model: "local".into(),
        purpose: "office.review".into(),
        privacy: Privacy::Sensitive,
        max_tokens: 32,
    };
    snapshot.domain.flows.insert(
        "review".into(),
        flows::Instance {
            workflow: None,
            template: "review".into(),
            template_epoch: 1,
            payload: OfficeAction::Review(input.clone()),
            input: Some(input),
            proposer: "worker".into(),
            proposer_device: worker.peer_id().to_string(),
            started_ms: 0,
            payer: node::protocol::PointAccount {
                club: "school".into(),
                member: "worker".into(),
            },
            allowance: Some(node::protocol::AiAllowance {
                scope: "office".into(),
                epoch: 1,
            }),
            current: 0,
            records: vec![flows::StageRecord {
                ai_runs: vec![flows::AiRun {
                    review: None,
                    retry_requested: false,
                    job: "job".into(),
                    device: worker.peer_id().to_string(),
                    usage: None,
                    charged_points: 0,
                    refunded_points: 0,
                    output: None,
                    error: None,
                }],
                ..Default::default()
            }],
            status: flows::Status::Active,
            deadline_ms: None,
        },
    );
    assert!(running(&snapshot, &worker, &job, &view)?);
    let (other, _) = snapshot
        .domain
        .inner
        .files
        .version(None, b"unrelated material")?;
    snapshot.domain.flows.get_mut("review").unwrap().payload = OfficeAction::Review(other);
    assert!(!running(&snapshot, &worker, &job, &view)?);
    snapshot.domain.flows.get_mut("review").unwrap().payload =
        OfficeAction::Review(job.input.clone());
    snapshot.domain.flows.get_mut("review").unwrap().status = flows::Status::Cancelled;
    assert!(!running(&snapshot, &worker, &job, &view)?);
    snapshot.domain.flows.get_mut("review").unwrap().status = flows::Status::Active;
    snapshot.domain.flows.get_mut("review").unwrap().deadline_ms = Some(0);
    assert!(!running(&snapshot, &worker, &job, &view)?);
    snapshot.domain.flows.get_mut("review").unwrap().deadline_ms = None;
    identities.log.mark_stale();
    assert!(running(&snapshot, &worker, &job, &view).is_err());
    Ok(())
}

#[test]
fn office_document_attachments_resolve_deduplicate_and_reject_unsupported_files() -> Result<()> {
    let mut files = events::office::files::FileStore::default();
    let (pdf, blocks) = files.version(None, b"%PDF-1.7\nfixture")?;
    for block in blocks {
        files.put(block)?;
    }
    let evidence = serde_json::json!({"first":{"cid":pdf,"requires_document_review":true},
        "nested":[{"cid":pdf,"requires_document_review":true}]});
    let (attachments, capabilities) =
        document_attachments(&files, &serde_json::to_vec(&evidence)?)?;
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].mime, "application/pdf");
    assert_eq!(
        base64::engine::general_purpose::STANDARD.decode(&attachments[0].data)?,
        b"%PDF-1.7\nfixture"
    );
    assert_eq!(
        capabilities,
        [
            node::protocol::LlmCapability::Pdf,
            node::protocol::LlmCapability::Vision
        ]
        .into()
    );
    let (text, blocks) = files.version(None, b"plain text")?;
    for block in blocks {
        files.put(block)?;
    }
    let unsupported = serde_json::json!({"cid":text,"requires_document_review":true});
    assert!(document_attachments(&files, &serde_json::to_vec(&unsupported)?).is_err());
    assert!(document_attachments(&files, b"plain input")?.0.is_empty());
    Ok(())
}
