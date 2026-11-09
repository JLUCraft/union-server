#[path = "../../../../union-core/tests/support/mod.rs"]
mod support;
use identity::Identity;
use node::{Node, NodeConfig};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
type Journal = authority::journal::Journal<league::application::Application>;

#[tokio::test]
async fn lan_discovery_pins_and_probes_announced_servers()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let host = Identity::generate();
        let terminal = Identity::generate();
        let identities = support::Identities::new(
            &[(&host, "host", "jlu"), (&terminal, "terminal", "jlu")],
            "host",
        );
        let identity_pin = identities.binding.genesis.clone();
        let directory = tempfile::tempdir()?;
        let journal = Arc::new(Mutex::new(Journal::open_with_namespace(
            directory.path().join("journal"),
            identities.genesis(),
            node::protocol::Namespace::builtin(),
        )?));
        let application_pin = journal.lock().await.genesis_hash().to_owned();
        assert_ne!(identity_pin, application_pin);
        let view = identities.log.view(Duration::from_secs(60))?;
        let log = Arc::new(Mutex::new(identities.log));
        let server = Arc::new(
            Node::start(
                host.clone(),
                NodeConfig {
                    listen: vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse()?],
                    lan_discovery: true,
                    ..NodeConfig::new(node::protocol::Namespace::builtin())
                },
            )
            .await?,
        );
        let serve_journal = tokio::spawn({
            let node = server.clone();
            let journal = journal.clone();
            let view = view.clone();
            async move {
                authority::journal::serve(&node, journal, view, authority::journal::PROTOCOL).await
            }
        });
        let serve_trust = tokio::spawn({
            let node = server.clone();
            async move { authority::trust::serve_with_view(&node, log, false, view).await }
        });
        tokio::task::yield_now().await;

        let found = league::discovery::discover_with_namespace(
            Identity::generate(),
            Some(Duration::from_secs(3)),
            node::protocol::Namespace::builtin(),
        )
        .await?;
        let discovered = found
            .iter()
            .find(|entry| entry.peer == server.peer_id())
            .ok_or("announced server not discovered")?;
        assert_eq!(discovered.federation, "jlucraft");
        assert_eq!(discovered.genesis_hash, identity_pin);
        assert_eq!(
            discovered.application.as_deref(),
            Some(application_pin.as_str())
        );
        // The returned address answered a real dial, so governance works over it directly.
        let probe = Node::start(
            terminal,
            NodeConfig::new(node::protocol::Namespace::builtin()),
        )
        .await?;
        probe.dial(discovered.address.parse()?).await?;
        let response = authority::journal::discover::<league::application::Application>(
            &probe,
            server.peer_id(),
            authority::journal::PROTOCOL,
        )
        .await;
        let snapshot = authority::journal::request::<league::application::Application>(
            &probe,
            server.peer_id(),
            discovered
                .application
                .as_deref()
                .ok_or("application pin missing")?,
            authority::journal::Request::Snapshot,
            authority::journal::PROTOCOL,
        )
        .await;
        let wrong_pin = authority::journal::request::<league::application::Application>(
            &probe,
            server.peer_id(),
            &discovered.genesis_hash,
            authority::journal::Request::Snapshot,
            authority::journal::PROTOCOL,
        )
        .await;
        probe.shutdown().await?;
        assert!(response.is_ok());
        let snapshot = snapshot?;
        assert!(snapshot.error.is_none());
        assert!(snapshot.state.is_some());
        let wrong_pin = wrong_pin?;
        assert!(wrong_pin.state.is_none());
        assert_eq!(
            wrong_pin.error,
            Some(protocol::Error::Protocol("genesis mismatch".into()).to_string())
        );

        // A terminal pinned to a different federation never auto-connects to this one.
        let pinned = league::discovery::connect_pinned(
            Identity::generate(),
            &identity_pin,
            Some(Duration::from_secs(3)),
            node::protocol::Namespace::builtin(),
        )
        .await?;
        assert_eq!(pinned.map(|server| server.peer), Some(server.peer_id()));
        let wrong = league::discovery::connect_pinned(
            Identity::generate(),
            &"0".repeat(64),
            Some(Duration::from_secs(3)),
            node::protocol::Namespace::builtin(),
        )
        .await?;
        assert!(wrong.is_none());

        serve_journal.abort();
        serve_trust.abort();
        let _ = serve_journal.await;
        let _ = serve_trust.await;
        Arc::try_unwrap(server)
            .map_err(|_| "server still shared")?
            .shutdown()
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
