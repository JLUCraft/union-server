use super::*;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use hmac::{Hmac, KeyInit, Mac};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey, pkcs8::DecodePublicKey};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
async fn paper_connection(
    mut stream: TcpStream,
    secret: Vec<u8>,
    profiles: Vec<Profile>,
) -> Result<()> {
    let handshake = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    let mut f = Fields::new(&handshake.body);
    assert_eq!(f.int()?, protocol::VERSION);
    f.text(255)?;
    f.bytes(2)?;
    let intention = f.int()?;
    if intention == 1 {
        protocol::read_frame(&mut stream).await?;
        let mut body = vec![];
        protocol::string(
            &serde_json::json!({"version":{"protocol":protocol::VERSION}}).to_string(),
            &mut body,
        )?;
        protocol::write_packet(&mut stream, Packet { id: 0, body }, None).await?;
        return Ok(());
    }
    let login = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    assert_eq!(login.id, 0);
    let mut identity = Fields::new(&login.body);
    let name = identity.text(16)?;
    let uuid = uuid::Uuid::from_slice(identity.bytes(16)?)?;
    let profile = profiles
        .iter()
        .find(|p| p.uuid == uuid && p.name == name)
        .ok_or_else(|| anyhow::anyhow!("unexpected backend profile"))?;
    let mut query = vec![];
    protocol::varint(u32::MAX, &mut query);
    protocol::string("velocity:player_info", &mut query)?;
    query.push(4);
    protocol::write_packet(&mut stream, Packet { id: 4, body: query }, None).await?;
    let response = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
    assert_eq!(response.id, 2);
    let mut f = Fields::new(&response.body);
    assert_eq!(f.int()?, -1);
    assert_eq!(f.bytes(1)?, [1]);
    let signature = f.bytes(32)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret)?;
    mac.update(f.remaining());
    mac.verify_slice(signature)?;
    assert_eq!(f.int()?, 1);
    assert_eq!(f.text(64)?, "127.0.0.2");
    assert_eq!(f.bytes(16)?, profile.uuid.as_bytes());
    assert_eq!(f.text(16)?, profile.name);
    let mut compression = vec![];
    protocol::varint(128, &mut compression);
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: compression,
        },
        None,
    )
    .await?;
    let mut body = profile.uuid.as_bytes().to_vec();
    protocol::string(&profile.name, &mut body)?;
    protocol::varint(0, &mut body);
    protocol::write_packet(&mut stream, Packet { id: 2, body }, Some(128)).await?;
    assert_eq!(
        Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 3,
            body: vec![],
        },
        Some(128),
    )
    .await?;
    assert_eq!(
        Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?.id,
        3
    );
    // A play packet larger than the compression threshold exercises actual zlib.
    protocol::write_packet(
        &mut stream,
        Packet {
            id: 1,
            body: vec![9; 512],
        },
        Some(128),
    )
    .await?;
    let _closed = protocol::read_frame(&mut stream).await;
    Ok(())
}

#[derive(Clone)]
struct Station {
    mode: Arc<AtomicUsize>,
    down: Arc<AtomicBool>,
    joined: Arc<Mutex<BTreeSet<String>>>,
    token: Arc<Mutex<String>>,
    uuid: uuid::Uuid,
}
impl Station {
    async fn authorize(&self, headers: &HeaderMap) -> std::result::Result<(), StatusCode> {
        crate::bearer::require_bearer(headers, self.token.lock().await.as_bytes())
    }
    fn competition(&self) -> Value {
        json!({
            "id":"cup", "club":"jlu", "title":"Cup", "resource":"arena",
            "organizer":"organizer", "host":"host", "scorer":"scorer",
            "rules":{"crossClub":false,"seats":1,"reconnectMinMs":100,"reconnectMaxMs":1000},
            "phase":"playing", "teams":{}, "online":[], "seats":{}, "played":[],
            "playerScores":{}, "teamScores":{}, "health":{}, "admitted":null,"schedule":null,
            "manualPause":false,"infrastructureDown":self.down.load(Ordering::SeqCst),"pausedSince":null,"epoch":1
        })
    }
}
async fn station_join(
    State(state): State<Station>,
    Query(query): Query<BTreeMap<String, String>>,
) -> std::result::Result<Json<Value>, StatusCode> {
    if query.get("username").map(String::as_str) != Some("Alice")
        || !state
            .joined
            .lock()
            .await
            .contains(query.get("serverId").ok_or(StatusCode::BAD_REQUEST)?)
    {
        return Err(StatusCode::NO_CONTENT);
    }
    Ok(Json(
        json!({"id":state.uuid.simple().to_string(),"name":"Alice","properties":[]}),
    ))
}
async fn station_admission(
    State(state): State<Station>,
    headers: HeaderMap,
) -> std::result::Result<Json<Value>, StatusCode> {
    state.authorize(&headers).await?;
    let mode = state.mode.load(Ordering::SeqCst);
    if mode == 3 {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(
        json!({"account":"account-alice", "route": if mode==1 || mode==4 {json!({"destination":"match","team":"alpha","epoch":if mode == 4 {2} else {1},"address":"gateway.test:25565"})} else {json!({"destination":"waiting"})}}),
    ))
}
async fn station_action(
    State(state): State<Station>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> std::result::Result<Json<Value>, StatusCode> {
    state.authorize(&headers).await?;
    if body["action"] == "infrastructure" {
        state
            .down
            .store(!body["healthy"].as_bool().unwrap(), Ordering::SeqCst);
    }
    Ok(Json(state.competition()))
}
struct Fixture {
    _directory: tempfile::TempDir,
    config: Config,
    address: SocketAddr,
    station: Station,
    witnesses: Witnesses,
    tasks: JoinSet<()>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let secret = directory.path().join("paper.secret");
        std::fs::write(&secret, "s".repeat(32))?;
        let token = directory.path().join("session.token");
        let initial = "initial-host-session-with-32-characters".to_string();
        std::fs::write(&token, &initial)?;
        let station = Station {
            mode: Arc::new(AtomicUsize::new(0)),
            down: Arc::new(AtomicBool::new(false)),
            joined: Arc::default(),
            token: Arc::new(Mutex::new(initial)),
            uuid: uuid::Uuid::from_u128(7),
        };
        let mut tasks = JoinSet::new();
        let skin = TcpListener::bind("127.0.0.1:0").await?;
        let site = SkinSite::try_from(format!("http://{}", skin.local_addr()?))?;
        let profile = Profile {
            uuid: station.uuid,
            name: "Alice".into(),
            textures: None,
        };
        let router = Router::new()
            .route(
                "/sessionserver/session/minecraft/hasJoined",
                get(station_join),
            )
            .route(
                "/api/leagues/cup",
                get(
                    |State(state): State<Station>, headers: HeaderMap| async move {
                        state.authorize(&headers).await?;
                        Ok::<_, StatusCode>(Json(state.competition()))
                    },
                ),
            )
            .route(
                &format!("/api/leagues/cup/admission/{}", station.uuid.simple()),
                get(station_admission),
            )
            .route(
                "/api/hosted-leagues",
                get(
                    |State(state): State<Station>, headers: HeaderMap| async move {
                        state.authorize(&headers).await?;
                        let leagues = if state.mode.load(Ordering::SeqCst) == 5 {
                            vec![]
                        } else {
                            vec![state.competition()]
                        };
                        Ok::<_, StatusCode>(Json(json!({"leagues":leagues})))
                    },
                ),
            )
            .route("/api/leagues/cup/actions", post(station_action))
            .with_state(station.clone());
        tasks.spawn(async move {
            let _ = axum::serve(skin, router).await;
        });
        let mut backends = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            backends.push(Backend {
                address: listener.local_addr()?,
                forwarding_secret: secret.clone(),
            });
            let profile = profile.clone();
            tasks.spawn(async move {
                let mut connections=JoinSet::new();
                loop {tokio::select! {
                    accepted=listener.accept()=>{let Ok((stream,_))=accepted else {break;};let profile=profile.clone();connections.spawn(async move {paper_connection(stream,vec![b's';32],vec![profile]).await});},
                    Some(result)=connections.join_next(),if !connections.is_empty()=>{assert!(matches!(result,Ok(Ok(()))),"Paper protocol failed: {result:?}");}
                }}
            });
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let config = Config {
            league: "auto".into(),
            bind: address,
            transfer: Transfer {
                host: "gateway.test".into(),
                port: 25565,
            },
            waiting: backends.remove(0),
            arena: backends.remove(0),
            skin_site: site,
            session_token: token,
        };
        config.validate()?;
        let central = Central::new(config.skin_site.clone(), config.session_token.clone())?;
        let key = Arc::new(RsaPrivateKey::new(&mut OsRng, 1024)?);
        let serving = config.clone();
        let witnesses = Witnesses::default();
        let collector = witnesses.clone();
        tasks.spawn(async move {
            serve_scheduled(serving, central, key, Arc::new(listener), collector)
                .await
                .unwrap();
        });
        Ok(Self {
            _directory: directory,
            config,
            address,
            station,
            witnesses,
            tasks,
        })
    }
    async fn encrypted(
        &self,
        uuid: uuid::Uuid,
        corrupt_challenge: bool,
    ) -> Result<crate::login::Encrypted<TcpStream>> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind("127.0.0.2:0".parse()?)?;
        let mut stream = socket.connect(self.address).await?;
        protocol::write_packet(
            &mut stream,
            handshake("untrusted-client.example", 1234, 2)?,
            None,
        )
        .await?;
        let mut body = Vec::new();
        protocol::string("Alice", &mut body)?;
        body.extend(uuid.as_bytes());
        protocol::write_packet(&mut stream, Packet { id: 0, body }, None).await?;
        let request = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
        assert_eq!(request.id, 1);
        let mut fields = Fields::new(&request.body);
        assert_eq!(fields.text(20)?, "");
        let size = fields.int()? as usize;
        let public = fields.bytes(size)?.to_vec();
        let size = fields.int()? as usize;
        let mut challenge = fields.bytes(size)?.to_vec();
        assert_eq!(fields.bytes(1)?, [1]);
        fields.finish()?;
        let secret = [42u8; 16];
        self.station
            .joined
            .lock()
            .await
            .insert(crate::login::server_id(&secret, &public));
        if corrupt_challenge {
            challenge[0] ^= 1;
        }
        let key = RsaPublicKey::from_public_key_der(&public)?;
        let mut body = Vec::new();
        for bytes in [&secret[..], &challenge] {
            let encrypted = key.encrypt(&mut OsRng, Pkcs1v15Encrypt, bytes)?;
            protocol::varint(encrypted.len() as u32, &mut body);
            body.extend(encrypted);
        }
        protocol::write_packet(&mut stream, Packet { id: 1, body }, None).await?;
        Ok(crate::login::Encrypted::new(stream, &secret))
    }
    async fn play(&self) -> Result<crate::login::Encrypted<TcpStream>> {
        let mut stream = self.encrypted(self.station.uuid, false).await?;
        let compression = Packet::decode(&protocol::read_frame(&mut stream).await?, None)?;
        assert_eq!(compression.id, 3);
        let success = Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?;
        assert_eq!(success.id, 2);
        let mut fields = Fields::new(&success.body);
        assert_eq!(fields.bytes(16)?, self.station.uuid.as_bytes());
        assert_eq!(fields.text(16)?, "Alice");
        protocol::write_packet(
            &mut stream,
            Packet {
                id: 3,
                body: vec![],
            },
            Some(128),
        )
        .await?;
        assert_eq!(
            Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?.id,
            3
        );
        protocol::write_packet(
            &mut stream,
            Packet {
                id: 3,
                body: vec![],
            },
            Some(128),
        )
        .await?;
        let play = Packet::decode(&protocol::read_frame(&mut stream).await?, Some(128))?;
        assert_eq!(play.body, vec![9; 512]);
        Ok(stream)
    }
    async fn transfer(&self, stream: &mut crate::login::Encrypted<TcpStream>) -> Result<()> {
        let packet = Packet::decode(
            &timeout(Duration::from_secs(12), protocol::read_frame(stream)).await??,
            Some(128),
        )?;
        assert_eq!(packet.id, protocol::PLAY_TRANSFER);
        let mut fields = Fields::new(&packet.body);
        assert_eq!(fields.text(255)?, "gateway.test");
        assert_eq!(fields.int()?, 25565);
        fields.finish()?;
        Ok(())
    }
}
#[tokio::test]
async fn encrypted_gateway_routes_accounts_and_fences_existing_sessions_on_revocation() -> Result<()>
{
    let mut fixture = Fixture::new().await?;
    let mut waiting = fixture.play().await?;
    let rotated = "rotated-host-session-with-32-characters".to_string();
    std::fs::write(&fixture.config.session_token, &rotated)?;
    *fixture.station.token.lock().await = rotated;
    fixture.station.mode.store(1, Ordering::SeqCst);
    fixture.transfer(&mut waiting).await?;
    let mut arena = fixture.play().await?;
    assert!(fixture.witnesses.recorded(
        "arena",
        "account-alice",
        &fixture.station.uuid.simple().to_string()
    ));
    fixture.station.mode.store(4, Ordering::SeqCst);
    fixture.transfer(&mut arena).await?;
    let mut substitute = fixture.play().await?;
    fixture.station.mode.store(2, Ordering::SeqCst);
    fixture.transfer(&mut substitute).await?;
    let mut paused = fixture.play().await?;
    fixture.station.mode.store(5, Ordering::SeqCst);
    assert!(
        timeout(Duration::from_secs(12), protocol::read_frame(&mut paused))
            .await?
            .is_err()
    );
    assert!(fixture.station.down.load(Ordering::SeqCst));
    fixture.tasks.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn encrypted_gateway_rejects_profile_substitution_challenge_forgery_and_duplicate_accounts()
-> Result<()> {
    let mut fixture = Fixture::new().await?;
    for (uuid, corrupt) in [
        (uuid::Uuid::from_u128(8), false),
        (fixture.station.uuid, true),
    ] {
        let mut client = fixture.encrypted(uuid, corrupt).await?;
        assert!(
            timeout(Duration::from_secs(12), protocol::read_frame(&mut client))
                .await?
                .is_err()
        );
    }
    let mut player = fixture.play().await?;
    let mut duplicate = fixture.encrypted(fixture.station.uuid, false).await?;
    assert!(
        timeout(
            Duration::from_secs(12),
            protocol::read_frame(&mut duplicate)
        )
        .await?
        .is_err()
    );
    fixture.station.mode.store(3, Ordering::SeqCst);
    assert!(
        timeout(Duration::from_secs(12), protocol::read_frame(&mut player))
            .await?
            .is_err()
    );
    fixture.tasks.shutdown().await;
    Ok(())
}
