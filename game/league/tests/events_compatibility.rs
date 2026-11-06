use events::{EventAction, EventsState, office, workflows};
use league::events as game;
use league::events;

#[test]
fn legacy_paths_and_mixed_state_keep_the_existing_wire_layout() {
    let state: game::EventsState = EventsState::default();
    let expected = r#"{"organization":{"automation":null,"resources":{},"schools":{},"enrollment":{},"plans":{},"reports":{},"points":{},"activity_policy":null,"oracle_sources":{},"activity_members":{},"activity_receipts":{},"ai_allowances":{},"ai_documents":{},"notices":{},"publications":{},"push_checkpoints":{}},"leagues":{},"events":{},"tasks":{},"signups":{},"checkins":{}}"#;
    assert_eq!(serde_json::to_string(&state).unwrap(), expected);
    assert_eq!(
        serde_json::from_str::<EventsState>(expected).unwrap(),
        state
    );
    let _: &league::LeagueState = &state;
    let report_kind: workflows::ReportKind = office::workflows::ReportKind::MuaAnnual;
    assert_eq!(
        serde_json::to_string(&report_kind).unwrap(),
        r#""mua_annual""#
    );
    let _: Option<office::points::BudgetAuthorization> =
        None::<events::points::BudgetAuthorization>;
    let _: Option<office::Event> = None::<events::Event>;
}

#[test]
fn office_and_game_actions_keep_existing_tags_and_fields() {
    for wire in [
        r#"{"type":"events.create","id":"meeting","title":"Meeting","brief_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","window":{"opens_ms":100,"closes_ms":200,"starts_ms":300}}"#,
        r#"{"type":"events.approve","id":"meeting","epoch":1,"co_organizers":["b"]}"#,
        r#"{"type":"organization.resource","id":"game","resource":{"title":"Game","address":"localhost","peer":"peer","host":"host","scorer":"scorer","seats":16,"cross_school":true,"automatic_teams":false,"operations_service":"ops","instance":"instance"}}"#,
        r#"{"type":"organization.game_receipt","event":"event","game":"game","started":true,"stopped":true,"results":{"alice":7},"evidence":null,"error":null}"#,
        r#"{"type":"organization.activity_policy","policy":{"daily_member_cap":100}}"#,
        r#"{"type":"organization.authorize_ai","scope":"report:annual","budget":25}"#,
        r#"{"type":"organization.report_publish","id":"annual"}"#,
        r#"{"type":"create_season","id":"season","title":"Season"}"#,
    ] {
        let action: EventAction = serde_json::from_str(wire).unwrap();
        let action: game::EventAction = action;
        assert_eq!(serde_json::to_string(&action).unwrap(), wire);
    }
}
