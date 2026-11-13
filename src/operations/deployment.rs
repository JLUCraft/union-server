use super::{
    Error, Result,
    config::{BackupSettings, InstanceSettings},
    fleet::directory,
};
use crate::operation_contracts::{OperationsDefinition, OperationsFileChange};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Write,
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

pub(super) const DEFINITION: &str = ".jlucraft-instance.json";
const CHANGES: &str = "changes.json";
const CONTENT: &str = "content";
const CANDIDATE: &str = "candidate";
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const HEALTH_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub definition: OperationsDefinition,
}
#[derive(Clone)]
pub(super) struct Prepared {
    pub request: String,
    pub scope: String,
    pub directory: PathBuf,
}
#[derive(Serialize, Deserialize)]
struct Change {
    path: PathBuf,
    content: Option<usize>,
    executable: bool,
}
pub(super) struct Deployment {
    pub directory: PathBuf,
    pub removed: PathBuf,
    origins: BTreeSet<String>,
    limits: BackupSettings,
    client: reqwest::Client,
}

fn relative(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || path.components().any(|c| c.as_os_str() == DEFINITION)
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Invalid(
            "file path must stay inside the instance".into(),
        ));
    }
    Ok(path)
}
fn change_parts(
    change: &OperationsFileChange,
) -> Result<(PathBuf, Option<&str>, Option<&str>, bool)> {
    match change {
        OperationsFileChange::Variant0 {
            path,
            text,
            executable,
        } => Ok((
            relative(&path.to_string())?,
            Some(text),
            None,
            executable.unwrap_or(false),
        )),
        OperationsFileChange::Variant1 {
            path,
            url,
            executable,
        } => Ok((
            relative(&path.to_string())?,
            None,
            Some(url),
            executable.unwrap_or(false),
        )),
        OperationsFileChange::Variant2 { path, .. } => {
            Ok((relative(&path.to_string())?, None, None, false))
        }
    }
}
pub(super) fn write_entry(root: &Path, entry: &Entry) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join(DEFINITION))?;
    file.write_all(&serde_json::to_vec(entry)?)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}
pub(super) fn read_entry(root: &Path) -> Result<Entry> {
    let path = root.join(DEFINITION);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_file()
        || metadata.is_symlink()
        || metadata.len() > crate::operation_contracts::OPERATIONS_MAX_REQUEST_BYTES as u64
    {
        return Err(Error::Invalid("invalid managed instance definition".into()));
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
pub(super) fn candidate(transaction: &Path) -> PathBuf {
    transaction.join(CANDIDATE)
}

impl Deployment {
    pub fn new(data: &Path, origins: &[String], limits: BackupSettings) -> Result<Self> {
        let prepared = directory(data, "deployments")?;
        let removed = directory(data, "removed")?;
        for root in [&prepared, &removed] {
            for entry in std::fs::read_dir(root)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    return Err(Error::Invalid("invalid deployment directory".into()));
                }
                std::fs::remove_dir_all(entry.path())?;
            }
        }
        let origins = origins
            .iter()
            .map(|value| {
                super::authority::endpoint(value).map(|url| url.origin().ascii_serialization())
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            directory: prepared,
            removed,
            origins,
            limits,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(TRANSFER_TIMEOUT)
                .build()?,
        })
    }

    pub async fn prepare(&self, id: &str, changes: &[OperationsFileChange]) -> Result<PathBuf> {
        let root = directory(&self.directory, id)?;
        let result = self.download(&root, changes).await;
        match result {
            Ok(()) => Ok(root),
            Err(error) => {
                Err(error.with_recovery(std::fs::remove_dir_all(&root).map_err(Error::from)))
            }
        }
    }
    async fn download(&self, root: &Path, changes: &[OperationsFileChange]) -> Result<()> {
        let content = directory(root, CONTENT)?;
        let mut manifest = Vec::new();
        let mut paths = BTreeSet::new();
        let mut total = 0_u64;
        for (index, change) in changes.iter().enumerate() {
            let (path, text, url, executable) = change_parts(change)?;
            if paths
                .iter()
                .any(|old: &PathBuf| path.starts_with(old) || old.starts_with(&path))
            {
                return Err(Error::Invalid("deployment paths overlap".into()));
            }
            paths.insert(path.clone());
            let present = text.is_some() || url.is_some();
            if present {
                let mut file = tokio::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(content.join(index.to_string()))
                    .await?;
                if let Some(text) = text {
                    total = total.saturating_add(text.len() as u64);
                    if total > self.limits.archive_bytes {
                        return Err(Error::Invalid("deployment exceeds byte quota".into()));
                    }
                    file.write_all(text.as_bytes()).await?;
                } else if let Some(url) = url {
                    let url = reqwest::Url::parse(url)
                        .map_err(|_| Error::Invalid("invalid artifact URL".into()))?;
                    if !url.username().is_empty()
                        || url.password().is_some()
                        || url.fragment().is_some()
                        || !self.origins.contains(&url.origin().ascii_serialization())
                    {
                        return Err(Error::Invalid("artifact origin is not permitted".into()));
                    }
                    let mut response = self.client.get(url).send().await?.error_for_status()?;
                    while let Some(chunk) = response.chunk().await? {
                        total = total.saturating_add(chunk.len() as u64);
                        if total > self.limits.archive_bytes {
                            return Err(Error::Invalid("deployment exceeds byte quota".into()));
                        }
                        file.write_all(&chunk).await?;
                    }
                }
                file.sync_all().await?;
            }
            manifest.push(Change {
                path,
                content: present.then_some(index),
                executable,
            });
        }
        let mut file = File::create(root.join(CHANGES))?;
        file.write_all(&serde_json::to_vec(&manifest)?)?;
        file.sync_all()?;
        File::open(&content)?.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(())
    }
    pub async fn apply(&self, prepared: &Path, candidate: &Path) -> Result<()> {
        let prepared = prepared.to_path_buf();
        let candidate = candidate.to_path_buf();
        let limits = self.limits.clone();
        tokio::task::spawn_blocking(move || {
            let changes: Vec<Change> =
                serde_json::from_slice(&std::fs::read(prepared.join(CHANGES))?)?;
            for change in changes {
                let path = relative(
                    change
                        .path
                        .to_str()
                        .ok_or_else(|| Error::Invalid("invalid file path".into()))?,
                )?;
                let mut target = candidate.clone();
                for part in path.components() {
                    target.push(part);
                    match std::fs::symlink_metadata(&target) {
                        Ok(metadata)
                            if metadata.is_symlink()
                                || !(metadata.is_dir() || metadata.is_file()) =>
                        {
                            return Err(Error::Invalid(
                                "deployment target contains a link or special file".into(),
                            ));
                        }
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if target.try_exists()? {
                    if target.is_dir() {
                        std::fs::remove_dir_all(&target)?;
                    } else {
                        std::fs::remove_file(&target)?;
                    }
                }
                if let Some(index) = change.content {
                    let parent = target
                        .parent()
                        .ok_or_else(|| Error::Invalid("missing parent".into()))?;
                    std::fs::create_dir_all(parent)?;
                    std::fs::copy(prepared.join(CONTENT).join(index.to_string()), &target)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &target,
                            std::fs::Permissions::from_mode(if change.executable {
                                0o700
                            } else {
                                0o600
                            }),
                        )?;
                    }
                    File::open(&target)?.sync_all()?;
                    File::open(parent)?.sync_all()?;
                }
            }
            let mut pending = vec![candidate.clone()];
            let mut bytes = 0_u64;
            let mut entries = 0_u64;
            while let Some(root) = pending.pop() {
                for entry in std::fs::read_dir(root)? {
                    let entry = entry?;
                    let metadata = entry.metadata()?;
                    if entry.file_type()?.is_symlink() || !(metadata.is_file() || metadata.is_dir())
                    {
                        return Err(Error::Invalid(
                            "instance contains a link or special file".into(),
                        ));
                    }
                    entries = entries.saturating_add(1);
                    if metadata.is_file() {
                        bytes = bytes.saturating_add(metadata.len());
                    } else {
                        pending.push(entry.path());
                    }
                    if entries > limits.entries || bytes > limits.archive_bytes {
                        return Err(Error::Invalid("deployed instance exceeds quota".into()));
                    }
                }
            }
            Ok(())
        })
        .await?
    }
}

pub(super) async fn healthy(
    managed: &super::fleet::Managed,
    profile: &InstanceSettings,
) -> Result<()> {
    let readiness = profile
        .readiness
        .as_ref()
        .ok_or_else(|| Error::Invalid("deployment requires profile readiness settings".into()))?;
    let started = std::time::Instant::now();
    let mut ready_at = None;
    loop {
        if managed.service.process_id().await.is_none()
            || !matches!(
                managed.service.state(),
                minecraftd::core::state::InstanceState::Running
            )
        {
            return Err(Error::Invalid(
                "deployed service exited before becoming healthy".into(),
            ));
        }
        let observed = std::time::Instant::now();
        if observed.duration_since(started) >= Duration::from_secs(readiness.timeout_seconds) {
            return Err(Error::Invalid(
                "deployed service readiness deadline expired".into(),
            ));
        }
        if managed.ready.load(std::sync::atomic::Ordering::SeqCst) {
            let at = ready_at.get_or_insert(observed);
            if observed.duration_since(*at) >= Duration::from_secs(readiness.stabilize_seconds) {
                return Ok(());
            }
        }
        tokio::time::sleep(HEALTH_POLL).await;
    }
}
