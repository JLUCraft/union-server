#[path = "../../../../union-core/tests/support/mod.rs"]
mod support;

use identity::Identity;
use league::{GAME_PROFILE, validate_game_profile};
use protocol::{Error, TrustAction};

#[test]
fn game_profile_evidence_binding_uniqueness_and_unbinding_preserve_authorization() {
    let player = Identity::generate();
    let other = Identity::generate();
    let verifier = Identity::generate();
    let mut ids = support::Identities::new(
        &[(&player, "player", "a"), (&other, "other", "a")],
        "player",
    );
    let root = ids.root("a");
    let bind = |member: &str, value: &str| TrustAction::BindAttribute {
        member: member.into(),
        club: "a".into(),
        kind: GAME_PROFILE.into(),
        value: value.into(),
    };
    let denied = |ids: &support::Identities, action: TrustAction, keys: &[&Identity]| {
        let mut record = ids.log.state().draft(action);
        for key in keys {
            identity::trust::sign_with_namespace(&mut record, key, ids.log.state().namespace())
                .unwrap();
        }
        assert!(matches!(
            ids.log.state().clone().apply(&record),
            Err(Error::Denied)
        ));
    };
    let value = "0123456789abcdef0123456789abcdef";
    validate_game_profile(value).unwrap();
    for evidence in ["institutional_email", GAME_PROFILE] {
        ids.append(
            TrustAction::AuthorizeVerifier {
                id: evidence.into(),
                club: "a".into(),
                device: verifier.peer_id().to_string(),
                evidence: [evidence.into()].into(),
            },
            &[&root, &verifier],
        );
        if evidence != GAME_PROFILE {
            denied(&ids, bind("player", value), &[&verifier, &player]);
        }
    }
    denied(&ids, bind("player", value), &[&verifier]);
    ids.append(bind("player", value), &[&verifier, &player]);
    assert_eq!(
        ids.log.state().attribute("player", GAME_PROFILE),
        Some(value)
    );
    denied(&ids, bind("other", value), &[&root, &other]);
    ids.append(
        TrustAction::RevokeVerifier {
            id: GAME_PROFILE.into(),
        },
        &[&root],
    );
    denied(&ids, bind("player", &"f".repeat(32)), &[&verifier, &player]);
    let unbind = TrustAction::UnbindAttribute {
        member: "player".into(),
        kind: GAME_PROFILE.into(),
    };
    denied(&ids, unbind.clone(), &[&verifier]);
    ids.append(unbind, &[&player]);
    assert_eq!(ids.log.state().attribute("player", GAME_PROFILE), None);
    ids.append(bind("other", value), &[&root, &other]);
    assert_eq!(
        ids.log.state().attribute("other", GAME_PROFILE),
        Some(value)
    );
}
