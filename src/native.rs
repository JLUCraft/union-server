//! Central-authority Minecraft TCP gateway with encrypted Yggdrasil login.
use crate::{
    activity::Witnesses,
    central::Central,
    forwarding::Profile,
    game_contracts::{
        Competition, CompetitionHealth, CompetitionList, CompetitionPhase, CompetitionRoute,
        CompetitionRouteVariant1Destination, GameHostAdmission,
    },
    protocol::{self, Fields, Packet},
    skins::SkinSite,
};
use anyhow::{Result, bail, ensure};
use reqwest::Method;
use rsa::{RsaPrivateKey, rand_core::OsRng};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};
const MAX_NATIVE_SESSIONS: usize = 128;
const MAX_RECOVERY_MS: u128 = 600_000;
const STATUS_DESCRIPTION: &str = "高校联赛";
const AUTHORIZATION_MAX_AGE: Duration = Duration::from_secs(10);
const MONITOR_INTERVAL: Duration = Duration::from_secs(1);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10);
pub trait GameStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> GameStream for T {}
type Connection = Box<dyn GameStream>;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub address: SocketAddr,
    pub forwarding_secret: PathBuf,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub host: String,
    pub port: u16,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub league: String,
    pub bind: SocketAddr,
    pub transfer: Transfer,
    pub waiting: Backend,
    pub arena: Backend,
    pub skin_site: SkinSite,
    pub session_token: PathBuf,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.league.is_empty()
                && self.league.len() <= 128
                && self
                    .league
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid league ID"
        );
        ensure!(
            !self.transfer.host.is_empty()
                && self.transfer.host.len() <= 255
                && self
                    .transfer
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
                && self.transfer.port != 0,
            "invalid gateway transfer address"
        );
        for backend in [&self.waiting, &self.arena] {
            ensure!(
                backend.address.ip().is_loopback() && backend.address.port() != 0,
                "Paper backend must use a fixed loopback port"
            );
            crate::forwarding::read_secret(&backend.forwarding_secret)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Room {
    Waiting,
    Arena(i64),
}
struct Active {
    id: u64,
    uuid: String,
    route: Option<Room>,
    checked: Instant,
    health: CompetitionHealth,
}
struct Runtime {
    central: Central,
    config: Config,
    witnesses: Witnesses,
    healthy: bool,
    presence_lock: Arc<Mutex<()>>,
    active: BTreeMap<String, Active>,
    disconnected: BTreeMap<String, Instant>,
    next: u64,
}
type Shared = Arc<Mutex<Runtime>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Login,
    LoginAck,
    Configuration,
    ConfigurationAck,
    Play,
    ReconfigurationAck,
}
impl Backend {
    async fn connect(&self) -> Result<Connection> {
        let stream = timeout(Duration::from_secs(5), TcpStream::connect(self.address)).await??;
        stream.set_nodelay(true)?;
        Ok(Box::new(stream))
    }
    async fn healthy(&self) -> bool {
        timeout(Duration::from_secs(3), async {
            let mut stream = self.connect().await?;
            protocol::write_packet(
                &mut stream,
                handshake("localhost", protocol::DEFAULT_MC_PORT, 1)?,
                None,
            )
            .await?;
            protocol::write_packet(
                &mut stream,
                Packet {
                    id: 0,
                    body: vec![],
                },
                None,
            )
            .await?;
            let status = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
            ensure!(status.id == 0, "invalid status");
            let mut fields = Fields::new(&status.body);
            let value: serde_json::Value = serde_json::from_str(fields.text(32767)?)?;
            fields.finish()?;
            ensure!(
                value["version"]["protocol"] == protocol::VERSION,
                "backend protocol mismatch"
            );
            Ok::<(), anyhow::Error>(())
        })
        .await
        .is_ok_and(|v| v.is_ok())
    }
    fn forwarding(&self, profile: &Profile, address: std::net::IpAddr) -> Result<Vec<u8>> {
        crate::forwarding::encode(&self.forwarding_secret, profile, address)
    }
}
fn handshake(host: &str, port: u16, intention: u32) -> Result<Packet> {
    let mut body = vec![];
    protocol::varint(protocol::VERSION as u32, &mut body);
    protocol::string(host, &mut body)?;
    body.extend(port.to_be_bytes());
    protocol::varint(intention, &mut body);
    Ok(Packet { id: 0, body })
}
async fn action(central: &Central, league: &str, body: serde_json::Value) -> Result<Competition> {
    let bytes = central
        .league(Method::POST, league, "actions", Some(body))
        .await
        .map_err(|code| anyhow::anyhow!("central game action rejected: {code}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}
async fn presence(
    shared: &Shared,
    member: &str,
    online: bool,
    health: CompetitionHealth,
) -> Result<()> {
    let (central, league, updates) = {
        let runtime = shared.lock().await;
        (
            runtime.central.clone(),
            runtime.config.league.clone(),
            runtime.presence_lock.clone(),
        )
    };
    let _guard = updates.lock().await;
    // Offline cleanup must not override a newly admitted connection for this account.
    if !online && shared.lock().await.active.contains_key(member) {
        return Ok(());
    }
    action(
        &central,
        &league,
        serde_json::json!({"action":"presence", "member":member, "online":online,"health":health}),
    )
    .await?;
    Ok(())
}
async fn admission(central: &Central, league: &str, uuid: &str) -> Result<GameHostAdmission> {
    let bytes = central
        .league(Method::GET, league, &format!("admission/{uuid}"), None)
        .await
        .map_err(|code| anyhow::anyhow!("game admission rejected: {code}"))?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn selected(admission: &GameHostAdmission, healthy: bool) -> Result<Room> {
    match &admission.route {
        CompetitionRoute::Variant0 {
            destination, epoch, ..
        } if destination == "match" => Ok(if healthy {
            Room::Arena(*epoch)
        } else {
            Room::Waiting
        }),
        CompetitionRoute::Variant1 {
            destination: CompetitionRouteVariant1Destination::Waiting,
        } => Ok(Room::Waiting),
        _ => bail!("player has no game route"),
    }
}
fn room(runtime: &Runtime, member: &str) -> Result<Room> {
    runtime
        .active
        .get(member)
        .filter(|active| active.checked.elapsed() < AUTHORIZATION_MAX_AGE)
        .and_then(|active| active.route.clone())
        .ok_or_else(|| anyhow::anyhow!("game authorization unavailable"))
}
async fn finish(shared: &Shared, member: &str, id: u64) -> Result<()> {
    let health = {
        let mut runtime = shared.lock().await;
        if !runtime.active.get(member).is_some_and(|s| s.id == id) {
            return Ok(());
        }
        let active = runtime
            .active
            .remove(member)
            .ok_or_else(|| anyhow::anyhow!("session vanished"))?;
        runtime.disconnected.insert(member.into(), Instant::now());
        active.health
    };
    if let Err(error) = presence(shared, member, false, health).await {
        tracing::debug!(%error, "offline presence unavailable");
    }
    Ok(())
}
async fn monitor(shared: Shared, changed: watch::Sender<()>) -> Result<()> {
    let mut interval = tokio::time::interval(MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let (central, config) = {
            let runtime = shared.lock().await;
            (runtime.central.clone(), runtime.config.clone())
        };
        let (a, b) = tokio::join!(config.waiting.healthy(), config.arena.healthy());
        let healthy = a && b;
        let update: Result<Competition> = async {
            let bytes = central
                .league(Method::GET, &config.league, "", None)
                .await
                .map_err(|code| anyhow::anyhow!("competition unavailable: {code}"))?;
            let mut league: Competition = serde_json::from_slice(&bytes)?;
            if league.infrastructure_down == healthy {
                league = action(
                    &central,
                    &config.league,
                    serde_json::json!({"action":"infrastructure", "healthy":healthy}),
                )
                .await?;
            }
            if healthy
                && league.phase == CompetitionPhase::Playing
                && league.paused_since.is_none()
                && league.seats.values().flatten().any(|seat| {
                    seat.disconnected_until
                        .is_some_and(|until| until <= now_ms())
                })
            {
                league = action(
                    &central,
                    &config.league,
                    serde_json::json!({"action":"tick"}),
                )
                .await?;
            }
            Ok(league)
        }
        .await;
        let entries: Vec<_> = {
            let mut runtime = shared.lock().await;
            runtime.healthy = healthy;
            runtime
                .active
                .iter()
                .map(|(member, active)| (member.clone(), active.uuid.clone(), active.id))
                .collect()
        };
        use futures::StreamExt;
        let checks = futures::stream::iter(entries)
            .map(|(member, uuid, id)| {
                let central = central.clone();
                let league = config.league.clone();
                async move {
                    let route = admission(&central, &league, &uuid)
                        .await
                        .and_then(|result| {
                            ensure!(result.account == member, "profile account changed");
                            selected(&result, healthy)
                        })
                        .ok();
                    (member, id, route, Instant::now())
                }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        let mut runtime = shared.lock().await;
        for (member, id, route, checked) in checks {
            if let Some(active) = runtime
                .active
                .get_mut(&member)
                .filter(|active| active.id == id)
            {
                active.route = route;
                active.checked = checked;
            }
        }
        let online = update.map(|league| league.online).unwrap_or_default();
        drop(runtime);
        for member in online {
            if let Err(error) = presence(&shared, &member, false, default_health(0)).await {
                tracing::debug!(%error, "stale presence cleanup unavailable");
            }
        }
        changed.send_replace(());
    }
}
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
fn default_health(recovery_ms: u64) -> CompetitionHealth {
    CompetitionHealth {
        rtt_ms: 0,
        jitter_ms: 0,
        recovery_ms: recovery_ms as i64,
    }
}
async fn reader<R: AsyncRead + Unpin>(mut read: R, tx: mpsc::Sender<Result<Vec<u8>>>) {
    loop {
        let packet = protocol::read_frame(&mut read).await;
        let failed = packet.is_err();
        if tx.send(packet).await.is_err() || failed {
            break;
        }
    }
}
async fn status<S: GameStream>(stream: &mut S, online: usize) -> Result<()> {
    let request = Packet::decode(&protocol::read_frame(stream).await?, None)?;
    ensure!(
        request.id == 0 && request.body.is_empty(),
        "invalid status request"
    );
    let value = serde_json::json!({
        "version": {"name": "26.3", "protocol": protocol::VERSION},
        "players": {"max": MAX_NATIVE_SESSIONS, "online": online},
        "description": {"text": STATUS_DESCRIPTION},
    })
    .to_string();
    let mut body = vec![];
    protocol::string(&value, &mut body)?;
    protocol::write_packet(stream, Packet { id: 0, body }, None).await?;
    let ping = Packet::decode(&protocol::read_frame(stream).await?, None)?;
    ensure!(ping.id == 1 && ping.body.len() == 8, "invalid ping");
    protocol::write_packet(stream, ping, None).await
}
async fn session(
    mut client: TcpStream,
    shared: Shared,
    key: Arc<RsaPrivateKey>,
    mut changed: watch::Receiver<()>,
) -> Result<()> {
    client.set_nodelay(true)?;
    let client_address = client.peer_addr()?.ip();
    let first = Packet::decode(
        &timeout(LOGIN_TIMEOUT, protocol::read_frame(&mut client)).await??,
        None,
    )?;
    ensure!(first.id == 0, "expected handshake");
    let mut fields = Fields::new(&first.body);
    let version = fields.int()?;
    fields.text(255)?;
    fields.bytes(2)?;
    let intention = fields.int()?;
    fields.finish()?;
    if intention == 1 {
        let online = shared.lock().await.active.len();
        return timeout(LOGIN_TIMEOUT, status(&mut client, online)).await?;
    }
    ensure!(
        version == protocol::VERSION && (intention == 2 || intention == 3),
        "unsupported Minecraft version or intention"
    );
    let login = Packet::decode(
        &timeout(LOGIN_TIMEOUT, protocol::read_frame(&mut client)).await??,
        None,
    )?;
    let (central, config) = {
        let runtime = shared.lock().await;
        (runtime.central.clone(), runtime.config.clone())
    };
    let (client, profile) = timeout(
        LOGIN_TIMEOUT,
        crate::login::authenticate(client, &login, &key, &config.skin_site),
    )
    .await??;
    let admitted = admission(&central, &config.league, &profile.uuid.simple().to_string()).await?;
    let checked = Instant::now();
    let league: Competition = serde_json::from_slice(
        &central
            .league(Method::GET, &config.league, "", None)
            .await
            .map_err(|code| anyhow::anyhow!("competition unavailable: {code}"))?,
    )?;
    ensure!(league.id == config.league, "unexpected competition");
    let resource = league.resource;
    let member = admitted.account.clone();
    let (id, selected, backend) = {
        let mut runtime = shared.lock().await;
        ensure!(
            !runtime.active.contains_key(&member),
            "member already connected"
        );
        let selected = selected(&admitted, runtime.healthy)?;
        let backend = match selected {
            Room::Waiting => config.waiting.clone(),
            Room::Arena(_) => config.arena.clone(),
        };
        runtime.next = runtime
            .next
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("session id exhausted"))?;
        let id = runtime.next;
        let recovery = runtime
            .disconnected
            .remove(&member)
            .map(|time| time.elapsed().as_millis().min(MAX_RECOVERY_MS) as u64)
            .unwrap_or(0);
        runtime.active.insert(
            member.clone(),
            Active {
                id,
                uuid: profile.uuid.simple().to_string(),
                route: Some(selected.clone()),
                checked,
                health: default_health(recovery),
            },
        );
        (id, selected, backend)
    };
    let result = async {
        let mut remote = backend.connect().await?;
        protocol::write_packet(
            &mut remote,
            handshake("localhost", protocol::DEFAULT_MC_PORT, 2)?,
            None,
        )
        .await?;
        let mut body = Vec::new();
        protocol::string(&profile.name, &mut body)?;
        body.extend(profile.uuid.as_bytes());
        protocol::write_packet(&mut remote, Packet { id: 0, body }, None).await?;
        let (cr, mut cw) = tokio::io::split(client);
        let (br, mut bw) = tokio::io::split(remote);
        let (ct, mut cx) = mpsc::channel(1);
        let (bt, mut bx) = mpsc::channel(1);
        let mut readers = JoinSet::new();
        readers.spawn(reader(cr, ct));
        readers.spawn(reader(br, bt));
        let mut watchdog = tokio::time::interval(MONITOR_INTERVAL);
        let mut stage = Stage::Login;
        let mut compression = None;
        let mut negotiation = crate::forwarding::LoginNegotiation::default();
        let mut keepalive: Option<(Vec<u8>, Instant)> = None;
        let mut announced = false;
        let mut witness = None;
        let mut started = Instant::now();
        loop {
            room(&*shared.lock().await, &member)?;
            if stage != Stage::Play && started.elapsed() > Duration::from_secs(120) {
                bail!("Minecraft login/configuration timed out");
            }
            if matches!(stage, Stage::Play | Stage::Configuration)
                && room(&*shared.lock().await, &member)? != selected
            {
                // Fence the old connection before issuing transfer; a reconnect may race
                // this task's final cleanup, which is guarded by the session generation.
                drop(witness.take());
                finish(&shared, &member, id).await?;
                let mut body = vec![];
                protocol::string(&config.transfer.host, &mut body)?;
                protocol::varint(u32::from(config.transfer.port), &mut body);
                protocol::write_packet(
                    &mut cw,
                    Packet {
                        id: if stage == Stage::Play {
                            protocol::PLAY_TRANSFER
                        } else {
                            protocol::CONFIGURATION_TRANSFER
                        },
                        body,
                    },
                    compression,
                )
                .await?;
                return Ok(());
            }
            let (from_client, raw) = tokio::select! {
                _ = watchdog.tick() => continue,
                update = changed.changed() => { update?; continue; },
                raw = cx.recv() => (true, raw),
                raw = bx.recv() => (false, raw),
            };
            if from_client {
                let raw = raw.ok_or_else(|| anyhow::anyhow!("client closed"))??;
                let p = Packet::decode(&raw, compression)?;
                match stage {
                    Stage::Login => ensure!(p.id == 4, "unexpected packet before login success"),
                    Stage::LoginAck => {
                        ensure!(
                            p.id == 3 && p.body.is_empty(),
                            "expected login acknowledgment"
                        );
                        stage = Stage::Configuration;
                    }
                    Stage::Configuration => {
                        ensure!(p.id != 3, "unsolicited configuration acknowledgment")
                    }
                    Stage::ConfigurationAck if p.id == 3 => {
                        ensure!(p.body.is_empty(), "invalid configuration acknowledgment");
                        stage = Stage::Play;
                        if matches!(selected, Room::Arena(_)) {
                            witness = Some(shared.lock().await.witnesses.begin(
                                &resource,
                                &profile.uuid.simple().to_string(),
                                &member,
                            )?);
                        }

                        if !announced {
                            let health = shared.lock().await.active[&member].health.clone();
                            presence(&shared, &member, true, health).await?;
                            announced = true;
                        }
                    }
                    Stage::ReconfigurationAck if p.id == protocol::PLAY_RECONFIGURE_ACK => {
                        ensure!(p.body.is_empty(), "invalid reconfiguration acknowledgment");
                        stage = Stage::Configuration;
                    }
                    _ => {}
                }
                if stage == Stage::Play
                    && p.id == protocol::PLAY_KEEPALIVE_REPLY
                    && let Some((expected, sent)) = keepalive.take()
                {
                    ensure!(p.body == expected, "unexpected keepalive reply");
                    let rtt = sent.elapsed().as_millis().min(60_000) as i64;
                    let mut runtime = shared.lock().await;
                    if let Some(active) = runtime.active.get_mut(&member) {
                        active.health.jitter_ms = (active.health.jitter_ms * 3
                            + active.health.rtt_ms.abs_diff(rtt) as i64)
                            / 4;
                        active.health.rtt_ms = rtt;
                    }
                }
                protocol::write_frame(&mut bw, &raw).await?;
                if let Some(witness) = &witness {
                    witness.touch();
                }
            } else {
                let raw = raw.ok_or_else(|| anyhow::anyhow!("backend closed"))??;
                let p = Packet::decode(&raw, compression)?;
                match stage {
                    Stage::Login => {
                        use crate::forwarding::LoginStep;
                        match negotiation.receive(&p, compression, &profile, || {
                            backend.forwarding(&profile, client_address)
                        })? {
                            LoginStep::Compression(threshold) => {
                                protocol::write_frame(&mut cw, &raw).await?;
                                compression = Some(threshold);
                                continue;
                            }
                            LoginStep::Reply(reply) => {
                                protocol::write_packet(&mut bw, reply, compression).await?;
                                continue;
                            }
                            LoginStep::Ready => stage = Stage::LoginAck,
                            LoginStep::Forward => {}
                        }
                    }
                    Stage::Configuration if p.id == 3 => {
                        ensure!(p.body.is_empty(), "invalid finish configuration");
                        stage = Stage::ConfigurationAck;
                    }
                    Stage::Play if p.id == protocol::PLAY_RECONFIGURE => {
                        ensure!(p.body.is_empty(), "invalid start configuration");
                        witness = None;
                        stage = Stage::ReconfigurationAck;
                        started = Instant::now();
                    }
                    Stage::Play if p.id == protocol::PLAY_KEEPALIVE => {
                        ensure!(p.body.len() == 8, "invalid keepalive");
                        keepalive = Some((p.body.clone(), Instant::now()));
                    }
                    Stage::Play if p.id == protocol::PLAY_TRANSFER => {
                        bail!("backend attempted unmanaged transfer")
                    }
                    Stage::Configuration if p.id == protocol::CONFIGURATION_TRANSFER => {
                        bail!("backend attempted unmanaged transfer")
                    }
                    _ => {}
                }
                protocol::write_frame(&mut cw, &raw).await?;
            }
        }
    }
    .await;
    finish(&shared, &member, id).await?;
    result
}
pub async fn start(config: Config, witnesses: Witnesses) -> Result<crate::Service> {
    config.validate()?;
    let central = Central::new(config.skin_site.clone(), config.session_token.clone())?;
    let key = tokio::task::spawn_blocking(|| RsaPrivateKey::new(&mut OsRng, 1024)).await??;
    let listener = Arc::new(TcpListener::bind(config.bind).await?);
    let address = listener.local_addr()?;
    Ok(crate::Service::spawn(
        "league_proxy",
        address,
        move |stopping| {
            serve_scheduled(
                config,
                central,
                Arc::new(key),
                listener,
                witnesses,
                stopping,
            )
        },
    ))
}
async fn serve_scheduled(
    config: Config,
    central: Central,
    key: Arc<RsaPrivateKey>,
    listener: Arc<TcpListener>,
    witnesses: Witnesses,
    mut stopping: oneshot::Receiver<()>,
) -> Result<()> {
    if config.league != "auto" {
        action(
            &central,
            &config.league,
            serde_json::json!({"action":"infrastructure","healthy":false}),
        )
        .await?;
        return serve_listener(config, central, key, listener, witnesses, stopping).await;
    }
    let mut tasks = JoinSet::new();
    let mut selected = String::new();
    let mut route_stop: Option<oneshot::Sender<()>> = None;
    let mut interval = tokio::time::interval(MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.reset();
    let mut initialized = false;
    loop {
        if initialized {
            tokio::select! {
                _=&mut stopping=>break,
                _=interval.tick()=>{},
                incoming=listener.accept(),if tasks.is_empty()=>{let (stream,_)=incoming?;drop(stream);continue;},
                result=tasks.join_next(),if !tasks.is_empty()=>{ if !matches!(result,Some(Ok(Ok(())))) {tracing::warn!("scheduled game route stopped");} selected.clear(); continue; }
            }
        }
        initialized = true;
        let candidate: Result<String> = async {
            let bytes = central
                .request(Method::GET, &["api", "hosted-leagues"], None)
                .await
                .map_err(|code| anyhow::anyhow!("host assignment unavailable: {code}"))?;
            let list: CompetitionList = serde_json::from_slice(&bytes)?;
            let games: Vec<_> = list
                .leagues
                .into_iter()
                .filter(|league| league.phase == CompetitionPhase::Playing)
                .collect();
            Ok(if games.len() == 1 {
                games[0].id.clone()
            } else {
                String::new()
            })
        }
        .await;
        let candidate = candidate.unwrap_or_default();
        if selected == candidate {
            continue;
        }
        if let Some(stop) = route_stop.take() {
            let _ = stop.send(());
        }
        let _ = timeout(AUTHORIZATION_MAX_AGE, tasks.join_next()).await;
        tasks.shutdown().await;
        selected = candidate;
        if !selected.is_empty() {
            let mut current = config.clone();
            current.league = selected.clone();
            let (central, key, listener) = (central.clone(), key.clone(), listener.clone());
            let witnesses = witnesses.clone();
            let (stop, stopped) = oneshot::channel();
            route_stop = Some(stop);
            tasks.spawn(async move {
                action(
                    &central,
                    &current.league,
                    serde_json::json!({"action":"infrastructure","healthy":false}),
                )
                .await?;
                serve_listener(current, central, key, listener, witnesses, stopped).await
            });
        }
    }
    if let Some(stop) = route_stop.take() {
        let _ = stop.send(());
    }
    let _ = timeout(AUTHORIZATION_MAX_AGE, tasks.join_next()).await;
    tasks.shutdown().await;
    Ok(())
}
async fn serve_listener(
    config: Config,
    central: Central,
    key: Arc<RsaPrivateKey>,
    listener: Arc<TcpListener>,
    witnesses: Witnesses,
    mut stopped: oneshot::Receiver<()>,
) -> Result<()> {
    let runtime = Runtime {
        central,
        config,
        witnesses,
        healthy: false,
        presence_lock: Arc::new(Mutex::new(())),
        active: BTreeMap::new(),
        disconnected: BTreeMap::new(),
        next: 0,
    };
    let shared = Arc::new(Mutex::new(runtime));
    let (changed, receiver) = watch::channel(());
    let monitor = monitor(shared.clone(), changed);
    tokio::pin!(monitor);
    let mut sessions = JoinSet::new();
    let result = loop {
        tokio::select! {
            result=&mut monitor=>break result,
            _=&mut stopped=>break Ok(()),
            incoming=listener.accept()=>{
                let (stream,_) = incoming?;
                if sessions.len() >= MAX_NATIVE_SESSIONS { drop(stream); continue; }
                let (shared,key,changed)=(shared.clone(),key.clone(),receiver.clone());
                sessions.spawn(async move { session(stream,shared,key,changed).await });
            },
            Some(result)=sessions.join_next(),if !sessions.is_empty()=>{match result{Ok(Ok(()))=>{},Ok(Err(error))=>tracing::debug!(%error,"game session ended"),Err(error)=>break Err(error.into())}}
        }
    };
    let cleanup = async {
        let (central, league) = {
            let runtime = shared.lock().await;
            (runtime.central.clone(), runtime.config.league.clone())
        };
        if let Err(error) = action(
            &central,
            &league,
            serde_json::json!({"action":"infrastructure","healthy":false}),
        )
        .await
        {
            tracing::debug!(%error,"game shutdown infrastructure update unavailable");
        }
        sessions.shutdown().await;
        let active: Vec<_> = shared
            .lock()
            .await
            .active
            .iter()
            .map(|(member, active)| (member.clone(), active.id))
            .collect();
        for (member, id) in active {
            finish(&shared, &member, id).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    if !matches!(timeout(Duration::from_secs(8), cleanup).await, Ok(Ok(()))) {
        tracing::warn!("game offline cleanup incomplete");
    }
    result
}
#[cfg(test)]
mod tests;
