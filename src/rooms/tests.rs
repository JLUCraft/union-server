use super::*;
use identity::Identity;
use node::{NodeConfig, RelayConfig};
use tokio::{io::AsyncReadExt, net::TcpListener};

fn login(profile: uuid::Uuid) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut handshake = vec![0];
    protocol::varint(777, &mut handshake);
    protocol::string("localhost", &mut handshake)?;
    handshake.extend(25565u16.to_be_bytes());
    protocol::varint(2, &mut handshake);
    let mut login = vec![0];
    protocol::string("Student", &mut login)?;
    login.extend(profile.as_bytes());
    Ok((handshake, login))
}

#[tokio::test]
async fn managed_room_publishes_after_readiness_and_withdraws_on_stop() -> Result<()> {
    timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("started");
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend = listener.local_addr()?;
        drop(listener);
        std::fs::write(dir.path().join("server.properties"), format!("server-ip=127.0.0.1\nserver-port={}\nonline-mode=false\n", backend.port()))?;
        let mut fixture = JoinSet::new();
        let ready = marker.clone();
        fixture.spawn(async move {
            while !ready.exists() { tokio::time::sleep(Duration::from_millis(10)).await; }
            let listener = TcpListener::bind(backend).await?;
            let (mut stream, _) = listener.accept().await?;
            protocol::read_frame(&mut stream).await?;
            protocol::read_frame(&mut stream).await?;
            let mut status = vec![0];
            protocol::string(r#"{"version":{"name":"26.3","protocol":777},"players":{"max":12,"online":0},"description":"room fixture"}"#, &mut status)?;
            protocol::write_frame(&mut stream, &status).await?;
            let ping = protocol::read_frame(&mut stream).await?;
            protocol::write_frame(&mut stream, &ping).await?;
            // Keep the backend listener alive until this fixture is dropped.
            std::future::pending::<Result<()>>().await
        });
        let host_identity = Identity::generate();
        let identities=crate::test_identity::Identities::new(&[(&host_identity,"host","a")],"host");
        let view=identities.log.view(Duration::from_secs(60))?;
        let mut host = Node::start(host_identity, NodeConfig::new(node::protocol::Namespace::jlucraft())).await?;
        let incoming=host.take_incoming()?;
        let host=Arc::new(host);
        let peer = host.peer_id();
        let address = host.addresses()[0].clone();
        let client = Node::start(Identity::generate(), NodeConfig::new(node::protocol::Namespace::jlucraft())).await?;
        client.dial(address).await?;
        assert!(client.list_services(peer).await?.is_empty());
        let key = dir.path().join("forwarding.key");
        std::fs::write(&key, "b".repeat(32))?;
        let config = HostConfig {
            forwarding_secret: key,
            skin_site: None,
            service: ServiceId::new().to_string(), name: "Managed room".into(),
            instance: InstanceConfig {
                id: "managed".into(), directory: dir.path().to_path_buf(), backend,
                server: ServerConfig { start_command: format!("sh -c 'touch \"$1\"; exec cat' sh '{}'", marker.display()),
                    stop_command: "^C".into(), ..Default::default() },
            },
            club:"a".into(),join_clubs:["a".into()].into(),
        };
        let room = LocalRoom::start(host.clone(), incoming, config, view, None).await?;
        assert_eq!(room.status().context("missing status")?.metadata.players_max, 12);
        assert_eq!(client.list_services(peer).await?.len(), 1);
        room.stop().await?;
        assert!(client.list_services(peer).await?.is_empty());
        client.shutdown().await?;
        fixture.shutdown().await;
        Ok::<_, anyhow::Error>(())
    }).await?
}

#[tokio::test]
async fn unified_members_from_two_clubs_join_over_relay_without_qualification_expiry() -> Result<()>
{
    timeout(Duration::from_secs(30), async {
        use node::protocol::{TrustAction, TrustFounder, TrustGenesis, TrustRequirement};
        let roots = [Identity::generate(), Identity::generate()];
        let users = [Identity::generate(), Identity::generate()];
        let genesis = TrustGenesis {
            namespace: node::protocol::Namespace::jlucraft(),
            quorum: 2,
            founders: roots
                .iter()
                .enumerate()
                .map(|(i, key)| TrustFounder {
                    member: format!("chair-{i}"),
                    club: format!("club-{i}"),
                    public_key: key.public_key().encode_protobuf(),
                })
                .collect(),
        };
        let directory = tempfile::tempdir()?;
        let pin = identity::trust::TrustState::genesis_digest(&genesis)?;
        let mut log = authority::trust::TrustLog::open_with_namespace(
            &directory.path().join("identity.jsonl"),
            &genesis,
            &pin,
            node::protocol::Namespace::jlucraft(),
        )?;
        for (i, user) in users.iter().enumerate() {
            for action in [
                TrustAction::ConfirmMember {
                    member: format!("person-{i}"),
                    club: format!("club-{i}"),
                    device: Some(user.peer_id().to_string()),
                    evidence: "manual".into(),
                    verifier: None,
                },
                TrustAction::BindAttribute {
                    member: format!("person-{i}"),
                    club: format!("club-{i}"),
                    kind: league::GAME_PROFILE.into(),
                    value: uuid::Uuid::from_u128(i as u128 + 1).simple().to_string(),
                },
            ] {
                let mut record = log.state().draft(action);
                identity::trust::sign_with_namespace(
                    &mut record,
                    &roots[i],
                    &node::protocol::Namespace::jlucraft(),
                )?;
                identity::trust::sign_with_namespace(
                    &mut record,
                    user,
                    &node::protocol::Namespace::jlucraft(),
                )?;
                log.append(record)?;
            }
        }
        log.mark_current()?;
        let view = log.view(Duration::from_secs(60))?;
        let relay = Node::start(
            Identity::generate(),
            NodeConfig {
                listen: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse()?],
                relay: Some(RelayConfig::default()),
                ..NodeConfig::new(node::protocol::Namespace::jlucraft())
            },
        )
        .await
        .context("start room relay")?;
        let mut external = relay.addresses()[0].clone();
        external.pop();
        relay.add_external_address(external).await?;
        let mut peers = Vec::new();
        for user in users {
            peers.push(
                Node::start(
                    user,
                    NodeConfig {
                        hole_punching: false,
                        ..NodeConfig::new(node::protocol::Namespace::jlucraft())
                    },
                )
                .await
                .context("start room member node")?,
            );
        }
        let mut receivers = Vec::new();
        let mut services = Vec::new();
        for peer in &mut peers {
            terminal_runtime::reserve_relays(peer, &relay.addresses())
                .await
                .context("reserve member relay circuit")?;
            receivers.push(peer.take_incoming()?);
            let service = ServiceId::new();
            services.push(service);
            peer.publish(Service {
                id: service,
                name: "member room".into(),
                protocol: ROOM_PROTOCOL.into(),
                metadata: vec![],
                access: AccessPolicy::Trust {
                    view: view.clone(),
                    requirement: TrustRequirement {
                        clubs: ["club-0".into(), "club-1".into()].into(),
                        permission: None,
                    },
                },
            })
            .await?;
        }
        // Reservations connect each member to the relay, not to the other member.
        // Establish both circuit routes before any fixture opens a room service.
        for (from, to) in [(0, 1), (1, 0)] {
            let circuit = peers[to]
                .addresses()
                .into_iter()
                .find(|a| a.to_string().contains("/p2p-circuit/"))
                .context("no relay circuit")?;
            peers[from].dial(circuit).await.with_context(|| {
                format!("dial room relay circuit from peer {from} to peer {to}")
            })?;
        }
        let secret = directory.path().join("forwarding");
        std::fs::write(&secret, "test-forwarding-key-at-least-32-bytes")?;
        // Generic trust accepts these values; the game consumer must reject them itself.
        for (kind, value) in [
            (league::GAME_PROFILE, "0123456789ABCDEF0123456789ABCDEF"),
            (league::GAME_PROFILE, "01234567-89ab-cdef-0123-456789abcdef"),
            ("other", "0123456789abcdef0123456789abcdef"),
        ] {
            let stream = peers[0]
                .open_service(peers[1].peer_id(), services[1])
                .await
                .context("open room for invalid attribute fixture from peer 0 to peer 1")?;
            let mut session = receivers[1].recv().await.context("no admission")?;
            let mut claims: node::protocol::TrustAdmission =
                serde_json::from_slice(session.claims.as_deref().context("no claims")?)?;
            claims.attributes = [(kind.into(), value.into())].into();
            session.claims = Some(serde_json::to_vec(&claims)?);
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let error = super::bridge(session, listener.local_addr()?, &secret, None, None)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains(if kind == league::GAME_PROFILE {
                    "denied"
                } else {
                    "member has no verified game profile"
                }),
                "{error}"
            );
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
            drop(stream);
        }
        for (from, to) in [(0, 1), (1, 0)] {
            let stream = peers[from]
                .open_service(peers[to].peer_id(), services[to])
                .await?;
            let session = receivers[to].recv().await.context("no unified admission")?;
            let claims: node::protocol::TrustAdmission =
                serde_json::from_slice(session.claims.as_deref().context("no claims")?)?;
            assert_eq!(claims.member, format!("person-{from}"));
            assert_eq!(
                claims.attributes.get(league::GAME_PROFILE),
                Some(&uuid::Uuid::from_u128(from as u128 + 1).simple().to_string())
            );
            // An authenticated device still cannot substitute another member's Minecraft UUID.
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let backend = listener.local_addr()?;
            let key = secret.clone();
            let bridge =
                tokio::spawn(
                    async move { super::bridge(session, backend, &key, None, None).await },
                );
            let mut stream = stream.compat();
            let (handshake, login) = login(uuid::Uuid::from_u128(to as u128 + 1))?;
            protocol::write_frame(&mut stream, &handshake).await?;
            protocol::write_frame(&mut stream, &login).await?;
            assert!(bridge.await?.is_err());
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        }
        // Complete the actual Paper forwarding handshake over the relay in both directions.
        let witnesses = crate::activity::Witnesses::default();
        for (from, to) in [(0, 1), (1, 0)] {
            let stream = peers[from]
                .open_service(peers[to].peer_id(), services[to])
                .await?;
            let session = receivers[to]
                .recv()
                .await
                .context("no valid room admission")?;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let backend = listener.local_addr()?;
            let key = secret.clone();
            let collector = witnesses.clone();
            let bridge = tokio::spawn(async move {
                super::bridge(session, backend, &key, None, Some(collector)).await
            });
            let mut stream = stream.compat();
            let profile = uuid::Uuid::from_u128(from as u128 + 1);
            let (handshake, login) = login(profile)?;
            protocol::write_frame(&mut stream, &handshake).await?;
            protocol::write_frame(&mut stream, &login).await?;
            let (mut remote, _) = listener.accept().await?;
            assert_eq!(protocol::read_frame(&mut remote).await?, handshake);
            assert_eq!(protocol::read_frame(&mut remote).await?, login);
            // Paper uses an unrestricted signed int as the opaque transaction ID.
            let transaction = if from == 0 { i32::MIN } else { -1 };
            let mut query = vec![4];
            protocol::varint(transaction as u32, &mut query);
            protocol::string("velocity:player_info", &mut query)?;
            query.push(4);
            protocol::write_frame(&mut remote, &query).await?;
            let reply = Packet::decode(&protocol::read_frame(&mut remote).await?, None)?;
            assert_eq!(reply.id, 2);
            assert_eq!(Fields::new(&reply.body).int()?, transaction);
            let mut success = vec![2];
            success.extend(profile.as_bytes());
            protocol::string("Student", &mut success)?;
            success.push(0);
            protocol::write_frame(&mut remote, &success).await?;
            assert_eq!(protocol::read_frame(&mut stream).await?, success);
            drop((remote, stream));
            bridge.await??;
            assert!(witnesses.recorded(
                &services[to].to_string(),
                &format!("person-{from}"),
                &profile.simple().to_string()
            ));
        }
        let ops = ServiceId::new();
        peers[1]
            .publish(Service {
                id: ops,
                name: "ops".into(),
                protocol: node::protocol::OPS_PROTOCOL.into(),
                metadata: vec![],
                access: AccessPolicy::Trust {
                    view: view.clone(),
                    requirement: TrustRequirement {
                        clubs: Default::default(),
                        permission: Some("manage".into()),
                    },
                },
            })
            .await?;
        assert!(
            peers[0]
                .open_service(peers[1].peer_id(), ops)
                .await
                .is_err()
        );
        let active = peers[0]
            .open_service(peers[1].peer_id(), services[1])
            .await?;
        let session = receivers[1].recv().await.context("no active session")?;
        // A healthy currentness refresh must not disconnect an existing session.
        log.mark_current()?;
        let mut stream = session.stream.compat();
        assert!(
            timeout(Duration::from_millis(50), stream.read_u8())
                .await
                .is_err()
        );
        let mut revoke = log.state().draft(TrustAction::RevokeMembership {
            member: "person-0".into(),
            club: "club-0".into(),
        });
        identity::trust::sign_with_namespace(
            &mut revoke,
            &roots[0],
            &node::protocol::Namespace::jlucraft(),
        )?;
        log.append(revoke)?;
        assert!(
            timeout(Duration::from_secs(2), stream.read_u8())
                .await?
                .is_err()
        );
        assert!(
            peers[0]
                .open_service(peers[1].peer_id(), services[1])
                .await
                .is_err()
        );
        drop((active, stream, receivers));
        for peer in peers {
            peer.shutdown().await?;
        }
        relay.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await?
}
