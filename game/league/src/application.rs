//! One organization application: activities, competitions, files, and approvals share one journal.
use crate::events;
use crate::{Error, Identity, Node, NodeConfig, Result};
use std::io::Read;

const MAX_APPLICATION_TEXT_BYTES: usize = 16 * 1024;

pub type Application = flows::Flows<events::EventsDomain>;
pub type Input = crate::generic::Input<Application>;
pub type Snapshot = state::State<Application>;
pub type Action = state::governance::Action<Application>;
pub type Authority = authority::authority::Authority<Application>;

pub fn competition(action: crate::LeagueAction) -> Action {
    Action::Domain(flows::FlowAction::Inner(events::EventAction::Competition(
        action,
    )))
}
pub async fn execute(
    identity: crate::Identity,
    input: Input,
) -> crate::Result<crate::journal::Response<Application>> {
    crate::generic::execute(identity, input, crate::journal::PROTOCOL).await
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    #[serde(rename = "type")]
    _kind: String,
    id: String,
    title: String,
    description: String,
    attachment: Option<String>,
    window: events::Window,
}
impl Draft {
    fn document(&self) -> Result<Vec<u8>> {
        if self.description.trim().is_empty()
            || self.description.len() > MAX_APPLICATION_TEXT_BYTES
            || self.title.trim().is_empty()
            || self.title.len() > 256
            || self.id.is_empty()
            || self.id.len() > 128
            || self.window.opens_ms >= self.window.closes_ms
            || self.window.closes_ms > self.window.starts_ms
        {
            return Err(Error::Denied);
        }
        serde_json::to_vec(
            &serde_json::json!({"description": self.description, "attachment": self.attachment}),
        )
        .map_err(protocol)
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    #[serde(rename = "type")]
    kind: String,
    instance: String,
    comment: String,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    #[serde(rename = "type")]
    _kind: String,
    local_path: String,
    branch: String,
    path: String,
    message: String,
}

/// Dispatch one application wire request. `text` is the same JSON the manager app sends,
/// including the per-request trust configuration. `inline` supplies document bytes for
/// `local.files.upload` when the caller has them in memory instead of on disk.
pub async fn execute_with_upload(
    identity: Identity,
    text: &str,
    inline: Option<Vec<u8>>,
) -> Result<crate::journal::Response<Application>> {
    let mut value: serde_json::Value = serde_json::from_str(text).map_err(protocol)?;
    if value["action"]["type"] == "local.points.request_ai" {
        return crate::points::request_text(identity, value).await;
    }
    let creating = value["action"]["type"] == "local.events.create";
    let amending = value["action"]["type"] == "local.events.amend";
    let reviewing = matches!(
        value["action"]["type"].as_str(),
        Some("local.flows.approve" | "local.flows.reject")
    );
    if !creating && !amending && !reviewing && value["action"]["type"] != "local.files.upload" {
        return crate::generic::execute(
            identity,
            serde_json::from_value(value).map_err(protocol)?,
            crate::journal::PROTOCOL,
        )
        .await;
    }
    let draft: Option<Draft> = if creating || amending {
        Some(serde_json::from_value(value["action"].take()).map_err(protocol)?)
    } else {
        None
    };
    let review: Option<Review> = if reviewing {
        let review: Review = serde_json::from_value(value["action"].take()).map_err(protocol)?;
        if review.comment.trim().is_empty() || review.comment.len() > MAX_APPLICATION_TEXT_BYTES {
            return Err(Error::Denied);
        }
        Some(review)
    } else {
        None
    };
    let upload: Upload = if let Some(draft) = &draft {
        Upload {
            _kind: "local.events.create".into(),
            local_path: String::new(),
            branch: format!("request-{}", draft.id),
            path: "application.json".into(),
            message: "application".into(),
        }
    } else if let Some(review) = &review {
        Upload {
            _kind: review.kind.clone(),
            local_path: String::new(),
            branch: crate::protocol::digest(
                format!("review:{}:{}", review.instance, identity.peer_id()).as_bytes(),
            ),
            path: crate::protocol::digest(review.comment.as_bytes()),
            message: "review".into(),
        }
    } else {
        serde_json::from_value(value["action"].take()).map_err(protocol)?
    };
    let input: crate::generic::Input<Application> =
        serde_json::from_value(value).map_err(protocol)?;
    let bytes = if let Some(bytes) = inline {
        bytes
    } else if let Some(draft) = &draft {
        draft.document()?
    } else if let Some(review) = &review {
        review.comment.as_bytes().to_vec()
    } else {
        let mut bytes = Vec::new();
        std::fs::File::open(&upload.local_path)?
            .take(events::files::MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        bytes
    };
    let (address, peer) = crate::endpoint(&input.address, &input.peer)?;
    let node = Node::start(identity.clone(), NodeConfig::default()).await?;
    let result = async {
        node.dial(address).await?;
        let log = tokio::sync::Mutex::new(input.identity.open()?);
        input.identity.synchronize(&node, &log).await?;
        let trust = log.into_inner();
        if let Some(attachment) = draft.as_ref().and_then(|d| d.attachment.as_ref()) {
            let cid = attachment.parse::<crate::protocol::Cid>().map_err(protocol)?;
            crate::files::snapshot(&node, peer, &input.genesis_hash)
                .await?
                .domain
                .inner
                .files
                .read(&cid)
                .map_err(protocol)?;
        }
        let document = crate::files::upload(
            &node,
            peer,
            &input.genesis_hash,
            &identity,
            crate::files::Upload {
                branch: &upload.branch,
                path: &upload.path,
                message: &upload.message,
                bytes: &bytes,
            },
            &trust,
        )
        .await?;
        if let Some(review) = review {
            let digest = crate::protocol::digest(&bytes);
            let value = if review.kind == "local.flows.approve" {
                serde_json::json!({"type":"flows.approve","instance":review.instance,"comment_hash":digest})
            } else {
                serde_json::json!({"type":"flows.reject","instance":review.instance,"reason":digest})
            };
            let action = serde_json::from_value(value).map_err(protocol)?;
            return crate::trust::execute::<Application>(
                &node,
                peer,
                &input.genesis_hash,
                &identity,
                &trust,
                action,
                crate::journal::PROTOCOL,
            )
            .await;
        }
        if let Some(draft) = draft {
            let value = if amending {
                serde_json::json!({"type":"events.revise","id":draft.id,"title":draft.title,"brief_hash":document.to_string(),"window":draft.window})
            } else {
                serde_json::json!({"type":"events.create","id":draft.id,"title":draft.title,"brief_hash":document.to_string(),"window":draft.window})
            };
            let action = serde_json::from_value(value).map_err(protocol)?;
            return crate::trust::execute::<Application>(
                &node,
                peer,
                &input.genesis_hash,
                &identity,
                &trust,
                action,
                crate::journal::PROTOCOL,
            )
            .await;
        }
        let mut response = crate::journal::request::<Application>(
            &node,
            peer,
            &input.genesis_hash,
            crate::journal::Request::Snapshot,
            crate::journal::PROTOCOL,
        )
        .await?;
        if let Some(state) = &response.state {
            response.identity_view = Some(state.identity_presentation(trust.state())?);
        }
        Ok(response)
    }
    .await;
    node.shutdown().await?;
    result
}

/// Dispatch an application request without in-memory upload bytes.
pub async fn execute_text(
    identity: Identity,
    text: &str,
) -> Result<crate::journal::Response<Application>> {
    execute_with_upload(identity, text, None).await
}

fn protocol(e: impl std::fmt::Display) -> Error {
    Error::Protocol(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn draft_accepts_text_without_attachment_and_rejects_invalid_windows() {
        let mut draft = Draft {
            _kind: "local.events.create".into(),
            id: "request-one".into(),
            title: "Application".into(),
            description: "Description".into(),
            attachment: None,
            window: events::Window {
                opens_ms: 1,
                closes_ms: 2,
                starts_ms: 3,
            },
        };
        assert!(draft.document().is_ok());
        draft.window.closes_ms = 1;
        assert!(draft.document().is_err());
        draft.window.closes_ms = 2;
        draft.description = " ".into();
        assert!(draft.document().is_err());
    }
}
