use super::{Error, Result, config::Config, now};
use crate::operation_contracts::{
    OPERATIONS_APPROVAL_ACTIONS, OPERATIONS_APPROVAL_SECONDS, OPERATIONS_CLAIM_HEADER,
    OPERATIONS_CLAIM_PATH, OPERATIONS_MAX_REQUEST_BYTES, OperationsDispatch, OperationsJob,
};
use std::time::Duration;

pub(super) fn endpoint(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| Error::Invalid("invalid central authority URL".into()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !(url.scheme() == "https"
            || url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))
    {
        return Err(Error::Invalid(
            "central authority requires an HTTPS origin or numeric loopback".into(),
        ));
    }
    Ok(url)
}
pub(super) struct Authority {
    client: reqwest::Client,
    url: reqwest::Url,
    credential: String,
}
impl Authority {
    pub fn new(config: &Config, credential: &[u8]) -> Result<Self> {
        let url = endpoint(&config.authority)?
            .join(&format!("{OPERATIONS_CLAIM_PATH}/{}/claim", config.host))
            .map_err(|_| Error::Invalid("invalid central claim URL".into()))?;
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()?,
            url,
            credential: String::from_utf8(credential.to_vec()).map_err(|_| Error::Unauthorized)?,
        })
    }
    pub async fn authorize(&self, job: &OperationsJob) -> Result<()> {
        let mut response = self
            .client
            .post(self.url.clone())
            .header(OPERATIONS_CLAIM_HEADER, &self.credential)
            .json(&serde_json::json!({"id":job.intent.id}))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Authorization);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > OPERATIONS_MAX_REQUEST_BYTES {
                return Err(Error::Authorization);
            }
            body.extend_from_slice(&chunk);
        }
        let grant: OperationsDispatch = serde_json::from_slice(&body)?;
        if grant.expires_at <= now()?
            || serde_json::to_value(&grant.intent)? != serde_json::to_value(&job.intent)?
            || serde_json::to_value(&grant.approval)? != serde_json::to_value(&job.approval)?
        {
            return Err(Error::Authorization);
        }
        let operation = serde_json::to_value(&job.intent.command.operation)?;
        if operation
            .get("action")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|action| OPERATIONS_APPROVAL_ACTIONS.contains(&action))
        {
            let approval = grant.approval.ok_or(Error::Authorization)?;
            let at = now()?;
            if approval.request != job.intent.id
                || approval.account != job.intent.actor.account
                || approval.approved_at > at
                || at - approval.approved_at >= OPERATIONS_APPROVAL_SECONDS
            {
                return Err(Error::Authorization);
            }
        }
        Ok(())
    }
}
