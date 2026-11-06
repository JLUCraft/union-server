use super::*;
use authority::journal::{Command as JournalCommand, TrustedCommand};
use base64::{Engine, engine::general_purpose::STANDARD};
use identity::trust::{TrustAction, TrustFounder, TrustGenesis, TrustRecord, TrustState};
use state::governance::Action;

#[test]
fn keygen_is_private_and_never_overwrites() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("agent.key");
    let generated = run(Operation::Keygen { out: key.clone() })?;
    let bytes = std::fs::read(&key)?;
    assert!(run(Operation::Keygen { out: key.clone() }).is_err());
    assert!(std::fs::read(&key)? == bytes);
    assert_eq!(run(Operation::Public { key: key.clone() })?, generated);
    let identity = Identity::load(&key)?;
    assert_eq!(generated.as_object().unwrap().len(), 2);
    assert_eq!(generated["peer"], identity.peer_id().to_string());
    assert_eq!(
        STANDARD.decode(generated["public_key"].as_str().unwrap())?,
        identity.public_key().encode_protobuf()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

fn fixture(identity: &Identity) -> Result<TrustState> {
    let genesis = TrustGenesis {
        federation: "agent-test".into(),
        founders: vec![TrustFounder {
            member: "founder".into(),
            club: "club".into(),
            public_key: identity.public_key().encode_protobuf(),
        }],
        quorum: 1,
    };
    Ok(TrustState::new(
        &genesis,
        &TrustState::genesis_digest(&genesis)?,
    )?)
}

#[test]
fn command_output_verifies_and_binds_all_fields() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("agent.key");
    let identity = Identity::generate();
    identity.save_new(&key)?;
    let command = TrustedCommand::<Application> {
        genesis: "a".repeat(64),
        previous: "b".repeat(64),
        identity: fixture(&identity)?.checkpoint().clone(),
        command: JournalCommand {
            revision: 0,
            expires_ms: 30_000,
            action: Action::AnchorDigest {
                id: "agent-smoke".into(),
                digest: "c".repeat(64),
            },
        },
    };
    let input = serde_json::to_string(&command)?;
    let output = run(Operation::SignCommand {
        key: key.clone(),
        input: input.clone(),
    })?;
    assert_eq!(output.as_object().unwrap().len(), 3);
    let decode = |field: &str| -> Result<Vec<u8>> {
        let encoded = output[field].as_str().unwrap();
        let bytes = STANDARD.decode(encoded)?;
        assert_eq!(STANDARD.encode(&bytes), encoded);
        Ok(bytes)
    };
    let mut signed = SignedCommand {
        payload: decode("payload")?,
        public_key: decode("public_key")?,
        signature: decode("signature")?,
    };
    let (peer, verified) = signed.verify::<Application>()?;
    assert_eq!(peer, identity.peer_id().to_string());
    assert_eq!(
        serde_json::to_value(verified)?,
        serde_json::to_value(command)?
    );
    let input_file = directory.path().join("command.json");
    std::fs::write(&input_file, input)?;
    assert_eq!(
        run(Operation::SignCommand {
            key,
            input: input_file.to_string_lossy().into_owned(),
        })?,
        output
    );
    signed.payload[0] ^= 1;
    assert!(signed.verify::<Application>().is_err());
    Ok(())
}

#[test]
fn record_output_verifies_and_can_be_appended() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("agent.key");
    let identity = Identity::generate();
    identity.save_new(&key)?;
    let mut state = fixture(&identity)?;
    let record = state.draft(TrustAction::RevokeMembership {
        member: "founder".into(),
        club: "club".into(),
    });
    let output = run(Operation::SignRecord {
        key: key.clone(),
        input: serde_json::to_string(&record)?,
    })?;
    assert!(output["signatures"][0]["public_key"].is_array());
    let mut signed: TrustRecord = serde_json::from_value(output.clone())?;
    assert_eq!(
        trust::verify_signatures(&signed)?,
        [identity.peer_id().to_string()].into()
    );
    state.apply(&signed)?;
    assert_eq!(state.checkpoint().sequence, 1);
    assert!(
        run(Operation::SignRecord {
            key: key.clone(),
            input: serde_json::to_string(&signed)?,
        })
        .is_err()
    );
    let second = Identity::generate();
    second.save_new(key.with_file_name("second.key"))?;
    let countersigned: TrustRecord = serde_json::from_value(run(Operation::SignRecord {
        key: key.with_file_name("second.key"),
        input: serde_json::to_string(&signed)?,
    })?)?;
    assert_eq!(trust::verify_signatures(&countersigned)?.len(), 2);
    assert!(countersigned.signatures.contains(&signed.signatures[0]));
    signed.previous = "d".repeat(64);
    assert!(trust::verify_signatures(&signed).is_err());
    Ok(())
}

#[test]
fn invalid_inputs_and_missing_arguments_fail_without_echoing_input() -> Result<()> {
    assert!(Cli::try_parse_from(["jlucraft-agent"]).is_err());
    for args in [
        vec!["keygen"],
        vec!["public"],
        vec!["sign-command", "--key", "absent.key"],
        vec!["sign-command", "--input", "-"],
        vec!["sign-record", "--key", "absent.key"],
        vec!["sign-record", "--input", "-"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("jlucraft-agent").chain(args)).is_err());
    }
    let directory = tempfile::tempdir()?;
    let key = directory.path().join("agent.key");
    assert!(run(Operation::Public { key: key.clone() }).is_err());
    Identity::generate().save_new(&key)?;
    for input in ["{}", "{", "{\"private-input-sentinel\":true}"] {
        for command in [
            Operation::SignCommand {
                key: key.clone(),
                input: input.into(),
            },
            Operation::SignRecord {
                key: key.clone(),
                input: input.into(),
            },
        ] {
            let error = run(command).unwrap_err().to_string();
            assert!(error.contains("invalid"));
            assert!(!error.contains("private-input-sentinel"));
        }
    }
    std::fs::write(&key, b"private-key-sentinel")?;
    let error = run(Operation::Public { key }).unwrap_err();
    assert!(!format!("{error:#}").contains("private-key-sentinel"));
    Ok(())
}
