use super::{Error, Result};
use crate::operation_contracts::OperationsIdentifier;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

const CONFIG_BYTES: u64 = 1024 * 1024;
const CREDENTIAL_CHARACTERS: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub data: PathBuf,
    pub credential_file: PathBuf,
    pub host: String,
    pub authority: String,
    pub instances: BTreeMap<String, InstanceSettings>,
    pub backups: BackupSettings,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSettings {
    pub retained: usize,
    pub retained_bytes: u64,
    pub archive_bytes: u64,
    pub entries: u64,
    pub remote: Option<RemoteSettings>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSettings {
    pub endpoint: String,
    pub credential_file: PathBuf,
    pub recipient: String,
    pub identity_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceSettings {
    pub start_command: String,
    pub stop_command: String,
    pub kind: InstanceKind,
    pub auto_start: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceKind {
    Java,
    Bedrock,
    Service,
}

impl InstanceKind {
    pub fn server_type(self) -> &'static str {
        match self {
            Self::Java => "minecraft/java",
            Self::Bedrock => "minecraft/bedrock",
            Self::Service => "universal",
        }
    }
}

pub(super) fn identifier(value: &str) -> Result<OperationsIdentifier> {
    value
        .to_owned()
        .try_into()
        .map_err(|_| Error::Invalid("invalid identifier".into()))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        if std::fs::metadata(&path)?.len() > CONFIG_BYTES {
            return Err(Error::Invalid("configuration is too large".into()));
        }
        let parent = path
            .parent()
            .ok_or_else(|| Error::Invalid("configuration directory missing".into()))?;
        let mut config: Self = serde_json::from_slice(&std::fs::read(&path)?)?;
        for value in [&mut config.data, &mut config.credential_file] {
            if value.is_relative() {
                *value = parent.join(&*value);
            }
        }
        if let Some(remote) = &mut config.backups.remote {
            for path in
                std::iter::once(&mut remote.credential_file).chain(remote.identity_file.iter_mut())
            {
                if path.is_relative() {
                    *path = parent.join(&*path);
                }
            }
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        identifier(&self.host)?;
        super::authority::endpoint(&self.authority)?;
        if !self.bind.ip().is_loopback() || !self.data.is_absolute() {
            return Err(Error::Invalid(
                "supervisor requires a loopback listener and absolute data directory".into(),
            ));
        }
        for (id, settings) in &self.instances {
            identifier(id)?;
            if settings.start_command.is_empty() {
                return Err(Error::Invalid(
                    "configure the instance command and server type".into(),
                ));
            }
        }
        if self.backups.retained == 0
            || self.backups.retained > crate::operation_contracts::OPERATIONS_MAX_BACKUPS
            || self.backups.archive_bytes == 0
            || self.backups.retained_bytes < self.backups.archive_bytes
            || self.backups.entries == 0
        {
            return Err(Error::Invalid(format!(
                "configure positive archive quotas and retain 1 to {} backups",
                crate::operation_contracts::OPERATIONS_MAX_BACKUPS
            )));
        }
        if let Some(remote) = &self.backups.remote {
            super::authority::endpoint(&remote.endpoint)?;
            remote
                .recipient
                .parse::<age::x25519::Recipient>()
                .map_err(|_| Error::Invalid("invalid age backup recipient".into()))?;
            private_text(&remote.credential_file)?;
            if let Some(path) = &remote.identity_file {
                private_text(path)?;
            }
        }
        self.credential()?;
        Ok(())
    }

    pub(super) fn credential(&self) -> Result<Vec<u8>> {
        let metadata = std::fs::symlink_metadata(&self.credential_file)?;
        if !metadata.is_file() || metadata.len() > CONFIG_BYTES {
            return Err(Error::Invalid("credential must be a regular file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(Error::Invalid(
                    "credential file permissions must be 0600".into(),
                ));
            }
        }
        let value = std::fs::read_to_string(&self.credential_file)?;
        let value = value.trim();
        if value.len() != CREDENTIAL_CHARACTERS
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::Invalid(
                "credential must contain 32 random bytes encoded as hexadecimal".into(),
            ));
        }
        Ok(value.as_bytes().to_vec())
    }
}

pub(super) fn private_text(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.is_symlink() || metadata.len() > CONFIG_BYTES {
        return Err(Error::Invalid(
            "secret must be a regular private file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(Error::Invalid(
                "secret file permissions must be 0600".into(),
            ));
        }
    }
    let value = std::fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::Invalid("secret file is empty".into()));
    }
    Ok(value.to_owned())
}
