use crate::{game_contracts::GameScoringSession, skins::SkinSite};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use reqwest::Method;
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc};

const MAX_REQUEST_BYTES: usize = 65536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub skin_site: SkinSite,
    pub session_token: PathBuf,
    pub token: PathBuf,
}

#[derive(Clone)]
struct Context {
    central: crate::central::Central,
    token: Arc<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Score {
    league: String,
    event: String,
    players: BTreeMap<String, i64>,
    teams: BTreeMap<String, i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    league: String,
}

impl Context {
    fn new(config: Config) -> Result<Self> {
        ensure!(
            config.bind.ip().is_loopback(),
            "scoring adapter must bind loopback"
        );
        let token = crate::central::credential(&config.token, 256)?;
        Ok(Self {
            central: crate::central::Central::new(config.skin_site, config.session_token)?,
            token: Arc::new(token.into_bytes()),
        })
    }
}

async fn session(
    State(context): State<Context>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> std::result::Result<Json<GameScoringSession>, StatusCode> {
    crate::bearer::require_bearer(&headers, &context.token)?;
    let body = context
        .central
        .league(Method::GET, &id, "scoring", None)
        .await?;
    let session: GameScoringSession =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_GATEWAY)?;
    if session.league.id != id {
        return Err(StatusCode::BAD_GATEWAY);
    }
    Ok(Json(session))
}

async fn score(
    State(context): State<Context>,
    headers: HeaderMap,
    Json(score): Json<Score>,
) -> std::result::Result<StatusCode, StatusCode> {
    crate::bearer::require_bearer(&headers, &context.token)?;
    context
        .central
        .league(
            Method::POST,
            &score.league,
            "actions",
            Some(serde_json::json!({
                "action": "score",
                "event": score.event,
                "players": score.players,
                "teams": score.teams,
            })),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finish(
    State(context): State<Context>,
    headers: HeaderMap,
    Json(finish): Json<Finish>,
) -> std::result::Result<StatusCode, StatusCode> {
    crate::bearer::require_bearer(&headers, &context.token)?;
    context
        .central
        .league(
            Method::POST,
            &finish.league,
            "actions",
            Some(serde_json::json!({"action": "finish"})),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn router(context: Context) -> Router {
    Router::new()
        .route("/v1/session/{id}", get(session))
        .route("/v1/score", post(score))
        .route("/v1/finish", post(finish))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(context)
}

pub async fn serve(config: Config) -> Result<()> {
    let address = config.bind;
    let context = Context::new(config)?;
    axum::serve(
        tokio::net::TcpListener::bind(address).await?,
        router(context),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use reqwest::Client;
    use serde_json::{Value, json};
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct Station(Arc<Mutex<(Vec<Value>, bool)>>);

    async fn station_action(
        State(station): State<Station>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> std::result::Result<Json<Value>, StatusCode> {
        let mut state = station.0.lock().await;
        let expected = if state.1 {
            b"rotated-scorer-session-with-32-characters".as_slice()
        } else {
            b"initial-scorer-session-with-32-characters".as_slice()
        };
        crate::bearer::require_bearer(&headers, expected)?;
        if body["event"] == "denied" {
            return Err(StatusCode::FORBIDDEN);
        }
        state.0.push(body);
        Ok(Json(json!({})))
    }

    #[tokio::test]
    async fn scoring_forwards_account_results_and_reloads_the_central_session() -> Result<()> {
        let station = Station::default();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", upstream.local_addr()?);
        let upstream_router = Router::new()
            .route("/api/leagues/cup/actions", post(station_action))
            .route(
                "/api/leagues/cup/scoring",
                get(|headers: HeaderMap| async move {
                    crate::bearer::require_bearer(
                        &headers,
                        b"initial-scorer-session-with-32-characters",
                    )?;
                    Ok::<_, StatusCode>(Json(json!({
                        "league": {
                            "id": "cup", "club": "jlu", "title": "Cup", "resource": "arena",
                            "organizer": "organizer-account", "host": "host-account",
                            "scorer": "scorer-account",
                            "rules": {"crossClub": false, "seats": 1, "reconnectMinMs": 100,
                                      "reconnectMaxMs": 1000},
                            "phase": "playing", "teams": {}, "online": [], "seats": {},
                            "played": [], "playerScores": {}, "teamScores": {}, "health": {},
                            "admitted": null, "schedule": null, "manualPause": false,
                            "infrastructureDown": false, "pausedSince": null, "epoch": 1
                        },
                        "profiles": {"player-account": ["0123456789abcdef0123456789abcdef"]}
                    })))
                }),
            )
            .with_state(station.clone());
        let upstream_task =
            tokio::spawn(async move { axum::serve(upstream, upstream_router).await });
        let directory = tempfile::tempdir()?;
        let session_path = directory.path().join("session");
        let plugin_path = directory.path().join("plugin");
        std::fs::write(&session_path, "initial-scorer-session-with-32-characters")?;
        std::fs::write(&plugin_path, "local-plugin-token-with-32-characters")?;
        let context = Context::new(Config {
            bind: "127.0.0.1:0".parse()?,
            skin_site: SkinSite::try_from(origin)?,
            session_token: session_path.clone(),
            token: plugin_path,
        })?;
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let local_origin = format!("http://{}", local.local_addr()?);
        let local_task = tokio::spawn(async move { axum::serve(local, router(context)).await });
        let client = Client::new();
        let snapshot = client
            .get(format!("{local_origin}/v1/session/cup"))
            .bearer_auth("local-plugin-token-with-32-characters")
            .send()
            .await?;
        assert_eq!(snapshot.status(), StatusCode::OK);
        let snapshot: Value = snapshot.json().await?;
        assert_eq!(
            snapshot["profiles"]["player-account"],
            json!(["0123456789abcdef0123456789abcdef"])
        );
        let score = json!({
            "league": "cup", "event": "first",
            "players": {"player-account": 9}, "teams": {"alpha": 9}
        });
        let response = client
            .post(format!("{local_origin}/v1/score"))
            .json(&score)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for payload in [&score, &score] {
            let response = client
                .post(format!("{local_origin}/v1/score"))
                .bearer_auth("local-plugin-token-with-32-characters")
                .json(payload)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        {
            let state = station.0.lock().await;
            assert_eq!(state.0.len(), 2);
            assert_eq!(state.0[0], state.0[1]);
            assert_eq!(
                state.0[0],
                json!({"action": "score", "event": "first",
                       "players": {"player-account": 9}, "teams": {"alpha": 9}})
            );
        }
        station.0.lock().await.1 = true;
        let response = client
            .post(format!("{local_origin}/v1/finish"))
            .bearer_auth("local-plugin-token-with-32-characters")
            .json(&json!({"league": "cup"}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        std::fs::write(&session_path, "rotated-scorer-session-with-32-characters")?;
        let response = client
            .post(format!("{local_origin}/v1/finish"))
            .bearer_auth("local-plugin-token-with-32-characters")
            .json(&json!({"league": "cup"}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = client
            .post(format!("{local_origin}/v1/score"))
            .bearer_auth("local-plugin-token-with-32-characters")
            .json(&json!({"league": "cup", "event": "denied", "players": {}, "teams": {}}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(station.0.lock().await.0.len(), 3);
        local_task.abort();
        upstream_task.abort();
        Ok(())
    }
}
