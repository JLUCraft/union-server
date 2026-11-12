//! Authenticated central service transport shared by game adapters.
use crate::skins::SkinSite;
use anyhow::{Result, ensure};
use axum::http::StatusCode;
use reqwest::{Client, Method, redirect::Policy};
use std::{
    io::Read,
    path::{Path as FilePath, PathBuf},
    time::Duration,
};
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_SESSION_TOKEN_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
#[derive(Clone)]
pub(crate) struct Central {
    client: Client,
    skin_site: SkinSite,
    session_token: PathBuf,
}
pub(crate) fn credential(path: &FilePath, maximum: usize) -> Result<String> {
    let mut value = String::new();
    std::fs::File::open(path)?
        .take((maximum + 3) as u64)
        .read_to_string(&mut value)?;
    ensure!(value.len() <= maximum + 2, "scoring credential too large");
    let value = value.trim();
    ensure!(
        (32..=maximum).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic()),
        "invalid scoring credential"
    );
    Ok(value.into())
}

impl Central {
    pub(crate) fn new(skin_site: SkinSite, session_token: PathBuf) -> Result<Self> {
        credential(&session_token, MAX_SESSION_TOKEN_BYTES)?;
        Ok(Self {
            client: Client::builder()
                .redirect(Policy::none())
                .timeout(REQUEST_TIMEOUT)
                .build()?,
            skin_site,
            session_token,
        })
    }
    pub(crate) async fn league(
        &self,
        method: Method,
        league: &str,
        operation: &str,
        body: Option<serde_json::Value>,
    ) -> std::result::Result<Vec<u8>, StatusCode> {
        if league.is_empty()
            || league.len() > 128
            || !league
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let mut segments = vec!["api", "leagues", league];
        segments.extend(operation.split('/').filter(|segment| !segment.is_empty()));
        self.request(method, &segments, body).await
    }
    pub(crate) async fn request(
        &self,
        method: Method,
        segments: &[&str],
        body: Option<serde_json::Value>,
    ) -> std::result::Result<Vec<u8>, StatusCode> {
        let token = credential(&self.session_token, MAX_SESSION_TOKEN_BYTES)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let url = self
            .skin_site
            .url(segments)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let mut request = self.client.request(method, url).bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                400 => StatusCode::BAD_REQUEST,
                401 | 403 => StatusCode::FORBIDDEN,
                404 => StatusCode::NOT_FOUND,
                409 => StatusCode::CONFLICT,
                429 => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(StatusCode::BAD_GATEWAY);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}
