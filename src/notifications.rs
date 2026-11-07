//! Web Push delivery with encrypted, quorum-replicated subscription checkpoints.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, ensure};
use authority::authority::Authority;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use events::office::{
    Task,
    workflows::{Notice, PushCheckpoint},
};
use identity::Identity;
use node::{
    IncomingSession,
    protocol::{
        ApplicationPushRequest as Request, ApplicationPushResponse as Response, JsonFrame,
        read_frame, write_frame,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
    time::Duration,
};
use web_push::{ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushMessageBuilder};

/// Notification data and checkpoint actions supplied by the application domain.
pub(crate) trait NotificationDomain: flows::Workflow {
    fn notices(state: &Self::State) -> &BTreeMap<String, Notice>;
    fn task<'a>(state: &'a Self::State, id: &str) -> Option<&'a Task>;
    fn is_open(state: &Self::State, event: &str) -> bool;
    fn checkpoint<'a>(state: &'a Self::State, group: &str) -> Option<&'a PushCheckpoint>;
    fn checkpoint_action(group: &str, expected: u64, ciphertext: String) -> Result<Self::Action>;
}

impl NotificationDomain for league::events::EventsDomain {
    fn notices(state: &Self::State) -> &BTreeMap<String, Notice> {
        &state.organization.notices
    }

    fn task<'a>(state: &'a Self::State, id: &str) -> Option<&'a Task> {
        state.tasks.get(id)
    }

    fn is_open(state: &Self::State, event: &str) -> bool {
        state
            .events
            .get(event)
            .is_some_and(|e| e.phase == events::office::Phase::Open)
    }

    fn checkpoint<'a>(state: &'a Self::State, group: &str) -> Option<&'a PushCheckpoint> {
        state.organization.push_checkpoints.get(group)
    }

    fn checkpoint_action(group: &str, expected: u64, ciphertext: String) -> Result<Self::Action> {
        ensure!(
            ciphertext.len() <= league::events::workflows::MAX_PUSH_CHECKPOINT_BYTES,
            "push checkpoint capacity reached"
        );
        Ok(league::events::EventAction::Organization(
            league::events::workflows::OrganizationAction::PushCheckpoint {
                group: group.into(),
                expected,
                ciphertext,
            },
        ))
    }
}

impl<D: NotificationDomain> NotificationDomain for flows::Flows<D> {
    fn notices(state: &Self::State) -> &BTreeMap<String, Notice> {
        D::notices(&state.inner)
    }

    fn task<'a>(state: &'a Self::State, id: &str) -> Option<&'a Task> {
        D::task(&state.inner, id)
    }

    fn is_open(state: &Self::State, event: &str) -> bool {
        D::is_open(&state.inner, event)
    }

    fn checkpoint<'a>(state: &'a Self::State, group: &str) -> Option<&'a PushCheckpoint> {
        D::checkpoint(&state.inner, group)
    }

    fn checkpoint_action(group: &str, expected: u64, ciphertext: String) -> Result<Self::Action> {
        Ok(flows::FlowAction::Inner(D::checkpoint_action(
            group, expected, ciphertext,
        )?))
    }
}

const MAX_SUBSCRIPTIONS: usize = 1000;
const RETRY_MS: u64 = 60_000;
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub service: String,
    pub key: PathBuf,
    pub store: PathBuf,
    pub vapid_key: PathBuf,
    #[serde(default = "default_hosts")]
    pub allowed_hosts: BTreeSet<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Subscription {
    member: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    challenge: String,
    verified: bool,
}
#[derive(Default, Serialize, Deserialize)]
struct Store {
    subscriptions: BTreeMap<String, Subscription>,
    sent: BTreeSet<String>,
}
pub(crate) async fn serve<D: NotificationDomain>(
    a: Authority<D>,
    config: Config,
    mut incoming: tokio::sync::mpsc::Receiver<IncomingSession>,
) -> Result<()> {
    let key = Identity::load(&config.key)?;
    let lock = private_file(&config.store.with_extension("lock"))?;
    lock.try_lock()?;
    require_private(&config.vapid_key)?;
    let pem = std::fs::read(&config.vapid_key)?;
    let vapid = URL_SAFE_NO_PAD
        .encode(VapidSignatureBuilder::from_pem_no_sub(pem.as_slice())?.get_public_key());
    let mut store: Store = if config.store.exists() {
        require_private(&config.store)?;
        ensure!(
            std::fs::metadata(&config.store)?.len() <= MAX_STORE_BYTES,
            "push store too large"
        );
        serde_json::from_slice(&std::fs::read(&config.store)?)?
    } else {
        Store::default()
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut updates = a.watch().await;
    let mut next_attempt = BTreeMap::<String, u64>::new();
    let cipher = Aes256Gcm::new_from_slice(&Sha256::digest(&pem))
        .map_err(|_| anyhow::anyhow!("push encryption key invalid"))?;
    let group = node::protocol::digest(vapid.as_bytes());

    // Import an existing private cache once, only if this group has no committed state.
    if !store.subscriptions.is_empty()
        && a.effect_epoch().is_some()
        && D::checkpoint(&a.stored_state().await.domain, &group).is_none()
    {
        replicate(&a, &key, &cipher, &group, 0, &store).await?;
    }
    loop {
        let mut revision;
        let current = a.stored_state().await;
        if let Some(checkpoint) = D::checkpoint(&current.domain, &group) {
            {
                store = decrypt(
                    &cipher,
                    &checkpoint.ciphertext,
                    &checkpoint_aad(&current, &group, checkpoint.revision),
                )?;
                revision = checkpoint.revision;
            }
        } else {
            store = Store::default();
            revision = 0;
        }

        tokio::select! {
            session=incoming.recv()=>{
                let Some(mut session)=session else {break;};
                let result=tokio::time::timeout(Duration::from_secs(20),async {
                    let frame:JsonFrame=read_frame(&mut session.stream).await?;
                    ensure!(frame.sequence==0&&frame.last,"invalid push envelope");
                    let request:Request=serde_json::from_slice(&frame.json)?;
                    let device=session.peer.to_string();
                    let identity=a.identity_view().state()?;
                    let member=identity.member_for_device(&device).context("device revoked")?.to_string();
                    ensure!(identity.permits(&device,&a.state(key.peer_id()).await?.core.identity.audience,&config.service,"use"),"push permission revoked");
                    match request {
                        Request::Info=>{},
                        Request::Subscribe{endpoint,p256dh,auth}=>{
                            validate_endpoint(&endpoint,&config.allowed_hosts)?;
                            ensure!(p256dh.len()==87 && auth.len()==22,"invalid push keys");
                            ensure!(store.subscriptions.len()<MAX_SUBSCRIPTIONS||store.subscriptions.contains_key(&device),"push capacity reached");
                            if !store.subscriptions.get(&device).is_some_and(|s|s.endpoint==endpoint&&s.p256dh==p256dh&&s.auth==auth&&s.verified) {
                                let challenge=uuid::Uuid::new_v4().to_string();
                                let sub=Subscription{member,endpoint,p256dh,auth,challenge:challenge.clone(),verified:false};
                                send(&client,&pem,&sub,&serde_json::json!({"challenge":challenge})).await?;
                                store.subscriptions.insert(device,sub);revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;
                            }
                        }
                        Request::Verify{challenge}=>{
                            let sub=store.subscriptions.get_mut(&device).context("subscription missing")?;
                            ensure!(sub.challenge==challenge && sub.member==member,"subscription challenge mismatch");sub.verified=true;revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;
                        }
                        Request::Unsubscribe=>{store.subscriptions.remove(&device);revision=replicate(&a,&key,&cipher,&group,revision,&store).await?;persist(&config.store,&store)?;},
                    }
                    Ok::<_,anyhow::Error>(())
                }).await;
                let response=Response{ok:matches!(result,Ok(Ok(()))),vapid:vapid.clone(),error:(!matches!(result,Ok(Ok(())))).then(||"Push registration failed".into())};
                let _=write_frame(&mut session.stream,&JsonFrame{json:serde_json::to_vec(&response)?,sequence:0,last:true}).await;
                if !response.ok {continue;}
            }
            result=updates.changed()=>{result.context("office closed")?;},
            _=tokio::time::sleep(Duration::from_secs(5))=>{},
        }
        if a.effect_epoch().is_none() {
            continue;
        }
        let Ok(snapshot) = a.state(key.peer_id()).await else {
            continue;
        };
        let now = authority::journal::now_ms()?;
        let Ok(identity) = a.identity_view().state() else {
            continue;
        };
        let mut dirty = false;
        let mut active_deliveries = BTreeSet::new();
        for (id, notice) in D::notices(&snapshot.domain) {
            let Some(task) = due_task::<D>(&snapshot.domain, notice, now) else {
                continue;
            };
            for (device, sub) in &store.subscriptions {
                let delivery = node::protocol::digest(
                    format!("{id}:{}:{device}:{}", notice.due_ms, sub.challenge).as_bytes(),
                );
                active_deliveries.insert(delivery.clone());
                if !sub.verified
                    || sub.member != notice.member
                    || store.sent.contains(&delivery)
                    || next_attempt.get(&delivery).is_some_and(|due| *due > now)
                {
                    continue;
                }
                if identity.member_for_device(device) != Some(&sub.member)
                    || !identity.permits(
                        device,
                        &snapshot.core.identity.audience,
                        &config.service,
                        "use",
                    )
                    || !identity.permits(
                        device,
                        &snapshot.core.identity.audience,
                        &snapshot.core.identity.service,
                        "read",
                    )
                {
                    continue;
                }
                let payload = serde_json::json!({"notice":id,"event":notice.event,"task":notice.task,"title":task.title});
                let request = send(&client, &pem, sub, &payload);
                tokio::pin!(request);
                let mut identity_updates = a.identity_view();
                let epoch = a.effect_epoch();
                let delivered = loop {
                    identity_updates.mark_seen();
                    updates.borrow_and_update();
                    let Ok(current) = a.state(key.peer_id()).await else {
                        break false;
                    };
                    let Ok(identity) = identity_updates.state() else {
                        break false;
                    };
                    if a.effect_epoch() != epoch
                        || epoch.is_none()
                        || identity.member_for_device(device) != Some(&sub.member)
                        || !identity.permits(
                            device,
                            &current.core.identity.audience,
                            &config.service,
                            "use",
                        )
                        || !identity.permits(
                            device,
                            &current.core.identity.audience,
                            &current.core.identity.service,
                            "read",
                        )
                        || D::notices(&current.domain).get(id) != Some(notice)
                        || D::task(&current.domain, &notice.task) != Some(task)
                        || !D::is_open(&current.domain, &notice.event)
                    {
                        break false;
                    }
                    tokio::select! {
                        result=&mut request=>break result.is_ok(),
                        _=identity_updates.changed()=>{},
                        _=updates.changed()=>{},
                        _=tokio::time::sleep(Duration::from_secs(1))=>{},
                    }
                };
                if delivered {
                    store.sent.insert(delivery.clone());
                    dirty = true;
                }
                next_attempt.insert(delivery, now.saturating_add(RETRY_MS));
            }
        }
        let sent_count = store.sent.len();
        store.sent.retain(|id| active_deliveries.contains(id));
        next_attempt.retain(|id, _| active_deliveries.contains(id));
        dirty |= sent_count != store.sent.len();
        if dirty || revision == 0 && !store.subscriptions.is_empty() {
            match replicate(&a, &key, &cipher, &group, revision, &store).await {
                Ok(_) => {
                    persist(&config.store, &store)?;
                }
                Err(_) => {
                    tracing::debug!("push checkpoint awaits authority");
                }
            }
        }
    }
    Ok(())
}
fn due_task<'a, D: NotificationDomain>(
    state: &'a D::State,
    notice: &Notice,
    now: u64,
) -> Option<&'a Task> {
    let task = D::task(state, &notice.task)?;
    (notice.due_ms <= now
        && notice.acknowledged_ms.is_none()
        && !task.done
        && task.assignee.as_deref() == Some(&notice.member)
        && D::is_open(state, &notice.event))
    .then_some(task)
}

fn private_file(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if path.exists() {
        require_private(path)?;
    }
    Ok(options.open(path)?)
}
fn persist(path: &std::path::Path, store: &Store) -> Result<()> {
    let temp = path.with_extension("pending");
    let mut file = private_file(&temp)?;
    file.set_len(0)?;
    file.write_all(&serde_json::to_vec(store)?)?;
    file.sync_all()?;
    std::fs::rename(temp, path)?;
    Ok(())
}
fn validate_endpoint(endpoint: &str, hosts: &BTreeSet<String>) -> Result<()> {
    ensure!(endpoint.len() <= 1000, "endpoint too long");
    let url = reqwest::Url::parse(endpoint)?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.host_str().is_some_and(|h| hosts.contains(h)),
        "unapproved push host"
    );
    Ok(())
}
async fn send(
    client: &reqwest::Client,
    pem: &[u8],
    sub: &Subscription,
    payload: &serde_json::Value,
) -> Result<()> {
    let subscription = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);
    let signature = VapidSignatureBuilder::from_pem(pem, &subscription)?.build()?;
    let bytes = serde_json::to_vec(payload)?;
    let mut builder = WebPushMessageBuilder::new(&subscription);
    builder.set_payload(ContentEncoding::Aes128Gcm, &bytes);
    builder.set_vapid_signature(signature);
    builder.set_ttl(3600);
    let message = builder.build()?;
    let payload = message.payload.context("push payload missing")?;
    let mut request = client
        .post(message.endpoint.to_string())
        .header("TTL", message.ttl)
        .header("Content-Encoding", payload.content_encoding.to_str())
        .header("Content-Type", "application/octet-stream");
    for (k, v) in payload.crypto_headers {
        request = request.header(k, v);
    }
    ensure!(
        request
            .body(payload.content)
            .send()
            .await?
            .status()
            .is_success(),
        "push delivery failed"
    );
    Ok(())
}

fn default_hosts() -> BTreeSet<String> {
    BTreeSet::from(["fcm.googleapis.com".into()])
}

fn require_private(path: &std::path::Path) -> Result<()> {
    crate::bootstrap::require_private(path, "push secret")
}

fn checkpoint_aad<D: state::Domain>(
    state: &state::State<D>,
    group: &str,
    revision: u64,
) -> Vec<u8> {
    format!(
        "{}:{}:{group}:{revision}",
        state.core.identity.audience, state.core.identity.service
    )
    .into_bytes()
}
fn decrypt(cipher: &Aes256Gcm, text: &str, aad: &[u8]) -> Result<Store> {
    let bytes = URL_SAFE_NO_PAD.decode(text)?;
    ensure!(bytes.len() > 12, "invalid push checkpoint");
    let nonce = Nonce::try_from(&bytes[..12]).map_err(|_| anyhow::anyhow!("invalid push nonce"))?;
    let plain = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &bytes[12..],
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("push checkpoint key mismatch"))?;
    Ok(serde_json::from_slice(&plain)?)
}
async fn replicate<D: NotificationDomain>(
    a: &Authority<D>,
    key: &Identity,
    cipher: &Aes256Gcm,
    group: &str,
    expected: u64,
    store: &Store,
) -> Result<u64> {
    let next = expected.checked_add(1).context("push revision exhausted")?;
    let uuid = uuid::Uuid::new_v4();
    let nonce =
        Nonce::try_from(&uuid.as_bytes()[..12]).map_err(|_| anyhow::anyhow!("invalid nonce"))?;
    let state = a.stored_state().await;
    let aad = checkpoint_aad(&state, group, next);
    let mut bytes = nonce.to_vec();
    bytes.extend(
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &serde_json::to_vec(store)?,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("push encryption failed"))?,
    );
    let ciphertext = URL_SAFE_NO_PAD.encode(bytes);
    a.apply(
        key,
        state::governance::Action::Domain(D::checkpoint_action(group, expected, ciphertext)?),
    )
    .await?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use state::Domain;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Office records with an application-defined open flag, independent of game phases.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct OfficeDomain;
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    struct OfficeState {
        notices: BTreeMap<String, Notice>,
        tasks: BTreeMap<String, Task>,
        open: BTreeSet<String>,
        checkpoints: BTreeMap<String, PushCheckpoint>,
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct CheckpointAction {
        group: String,
        expected: u64,
        ciphertext: String,
    }
    impl Domain for OfficeDomain {
        type State = OfficeState;
        type Action = CheckpointAction;

        fn transition(
            state: &mut Self::State,
            _: &state::Context<'_>,
            action: Self::Action,
        ) -> node::Result<()> {
            if state
                .checkpoints
                .get(&action.group)
                .map_or(0, |c| c.revision)
                != action.expected
            {
                return Err(node::Error::Denied);
            }
            state.checkpoints.insert(
                action.group,
                PushCheckpoint {
                    revision: action.expected + 1,
                    ciphertext: action.ciphertext,
                },
            );
            Ok(())
        }
    }
    impl flows::Workflow for OfficeDomain {}
    impl NotificationDomain for OfficeDomain {
        fn notices(state: &Self::State) -> &BTreeMap<String, Notice> {
            &state.notices
        }
        fn task<'a>(state: &'a Self::State, id: &str) -> Option<&'a Task> {
            state.tasks.get(id)
        }
        fn is_open(state: &Self::State, event: &str) -> bool {
            state.open.contains(event)
        }
        fn checkpoint<'a>(state: &'a Self::State, group: &str) -> Option<&'a PushCheckpoint> {
            state.checkpoints.get(group)
        }
        fn checkpoint_action(
            group: &str,
            expected: u64,
            ciphertext: String,
        ) -> Result<Self::Action> {
            Ok(CheckpointAction {
                group: group.into(),
                expected,
                ciphertext,
            })
        }
    }

    #[test]
    fn office_domain_controls_notice_eligibility_without_game_phases() {
        type Office = flows::Flows<OfficeDomain>;
        let mut snapshot = flows::FlowsState::<OfficeDomain>::default();
        let notice = Notice {
            event: "meeting".into(),
            task: "minutes".into(),
            member: "secretary".into(),
            due_ms: 10,
            acknowledged_ms: None,
        };
        snapshot
            .inner
            .notices
            .insert("reminder".into(), notice.clone());
        snapshot.inner.tasks.insert(
            "minutes".into(),
            Task {
                event: "meeting".into(),
                title: "Write minutes".into(),
                assignee: Some("secretary".into()),
                done: false,
                due_ms: Some(10),
            },
        );
        assert_eq!(Office::notices(&snapshot).get("reminder"), Some(&notice));
        assert!(due_task::<Office>(&snapshot, &notice, 10).is_none());
        snapshot.inner.open.insert("meeting".into());
        assert!(due_task::<Office>(&snapshot, &notice, 9).is_none());
        assert_eq!(
            due_task::<Office>(&snapshot, &notice, 10).unwrap().title,
            "Write minutes"
        );
        let acknowledged = Notice {
            acknowledged_ms: Some(10),
            ..notice.clone()
        };
        assert!(due_task::<Office>(&snapshot, &acknowledged, 10).is_none());
        snapshot.inner.tasks.get_mut("minutes").unwrap().done = true;
        assert!(due_task::<Office>(&snapshot, &notice, 10).is_none());
        snapshot.inner.tasks.get_mut("minutes").unwrap().done = false;
        snapshot.inner.tasks.get_mut("minutes").unwrap().assignee = Some("other".into());
        assert!(due_task::<Office>(&snapshot, &notice, 10).is_none());
        snapshot.inner.tasks.clear();
        assert!(due_task::<Office>(&snapshot, &notice, 10).is_none());
    }

    #[tokio::test]
    async fn office_domain_replicates_encrypted_checkpoints_and_rejects_stale_revisions()
    -> Result<()> {
        type Office = flows::Flows<OfficeDomain>;
        // Compile the complete service for the non-game composition, including cancellation checks.
        let _service = serve::<Office>;
        let dir = tempfile::tempdir()?;
        let key = Identity::generate();
        let identities =
            crate::test_identity::Identities::new(&[(&key, "secretary", "school")], "secretary");
        let genesis = identities.genesis::<Office>();
        let authority = Authority::Local {
            journal: Arc::new(Mutex::new(
                authority::journal::Journal::open_with_namespace(
                    dir.path().join("office"),
                    genesis.clone(),
                    node::protocol::Namespace::jlucraft(),
                )?,
            )),
            view: identities.log.view(Duration::from_secs(60))?,
            log: Arc::new(Mutex::new(identities.log)),
        };
        let cipher = Aes256Gcm::new_from_slice(&[7; 32]).unwrap();
        let mut store = Store::default();
        store.sent.insert("delivered".into());
        let revision = replicate(&authority, &key, &cipher, "push", 0, &store).await?;
        assert_eq!(revision, 1);
        let current = authority.stored_state().await;
        let checkpoint = Office::checkpoint(&current.domain, "push").unwrap();
        let aad = checkpoint_aad(&current, "push", revision);
        assert_eq!(
            decrypt(&cipher, &checkpoint.ciphertext, &aad)?.sent,
            store.sent
        );
        for wrong_aad in [
            checkpoint_aad(&current, "other", revision),
            checkpoint_aad(&current, "push", 2),
        ] {
            assert!(decrypt(&cipher, &checkpoint.ciphertext, &wrong_aad).is_err());
        }
        let mut other = current.clone();
        other.core.identity.service = "other".into();
        assert!(
            decrypt(
                &cipher,
                &checkpoint.ciphertext,
                &checkpoint_aad(&other, "push", revision)
            )
            .is_err()
        );
        other = current.clone();
        other.core.identity.audience = Identity::generate().peer_id().to_string();
        assert!(
            decrypt(
                &cipher,
                &checkpoint.ciphertext,
                &checkpoint_aad(&other, "push", revision)
            )
            .is_err()
        );
        assert!(
            replicate(&authority, &key, &cipher, "push", 0, &store)
                .await
                .is_err()
        );
        assert_eq!(authority.stored_state().await, current);
        store.sent.insert("second".into());
        assert_eq!(
            replicate(&authority, &key, &cipher, "push", 1, &store).await?,
            2
        );
        let current = authority.stored_state().await;
        let checkpoint = Office::checkpoint(&current.domain, "push").unwrap();
        assert_eq!(
            decrypt(
                &cipher,
                &checkpoint.ciphertext,
                &checkpoint_aad(&current, "push", 2)
            )?
            .sent,
            store.sent
        );
        drop(authority);
        let replay = authority::journal::Journal::<Office>::open_with_namespace(
            dir.path().join("office"),
            genesis,
            node::protocol::Namespace::jlucraft(),
        )?;
        assert_eq!(replay.state(), &current);
        Ok(())
    }

    #[test]
    fn game_adapter_preserves_checkpoint_action_and_size_limit() -> Result<()> {
        type Game = flows::Flows<league::events::EventsDomain>;
        let action = Game::checkpoint_action("push", 3, "encrypted".into())?;
        assert_eq!(
            action,
            flows::FlowAction::Inner(league::events::EventAction::Organization(
                league::events::workflows::OrganizationAction::PushCheckpoint {
                    group: "push".into(),
                    expected: 3,
                    ciphertext: "encrypted".into()
                }
            ))
        );
        assert!(
            Game::checkpoint_action(
                "push",
                3,
                "x".repeat(league::events::workflows::MAX_PUSH_CHECKPOINT_BYTES + 1)
            )
            .is_err()
        );
        Ok(())
    }
}
