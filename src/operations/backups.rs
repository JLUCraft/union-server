use super::{
    Error, Result,
    config::{BackupSettings, private_text},
    jobs::Jobs,
};
use crate::operation_contracts::{OperationsBackup, OperationsBackupPage};
use minecraftd::{
    archive::{
        compress::ArchiveLimits,
        manager::{ArchiveConfig, ArchiveManager, ArchiveRequest},
        metadata::{ArchiveMetadata, CompressionAlgorithm, METADATA_BYTES},
        strategy::FullArchiveStrategy,
    },
    core::state::InstanceState,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;

const CANDIDATE: &str = "candidate";
const JOURNAL: &str = "journal";
const PENDING_JOURNAL: &str = "journal.pending";
const ENCRYPTED_ARCHIVE: &str = "encrypted.age";
const ENCRYPTION_OVERHEAD_DIVISOR: u64 = 1024;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    scope: String,
    archive: ArchiveMetadata,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    previous: DirectoryIdentity,
    safety: String,
}

#[derive(Clone)]
pub(super) struct Prepared {
    pub archive: ArchiveMetadata,
    pub scope: String,
    pub request: String,
    pub transaction: PathBuf,
}

fn directory_identity(path: &Path) -> Result<DirectoryIdentity> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err(Error::Invalid("restore directory is invalid".into()));
        }
        Ok(DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(Error::Invalid("atomic restore requires Linux".into()))
    }
}
fn exchange(left: &Path, right: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        nix::fcntl::renameat2(
            nix::fcntl::AT_FDCWD,
            left,
            nix::fcntl::AT_FDCWD,
            right,
            nix::fcntl::RenameFlags::RENAME_EXCHANGE,
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (left, right);
        Err(Error::Invalid("atomic restore requires Linux".into()))
    }
}

pub(super) struct Backups {
    pub archives: ArchiveManager,
    transactions: PathBuf,
    transfer: PathBuf,
    settings: BackupSettings,
    jobs: Arc<Jobs>,
    client: reqwest::Client,
}
fn sync(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
fn remove_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {
            std::fs::remove_dir_all(path)?;
            Ok(())
        }
        Ok(_) => Err(Error::Invalid(
            "backup transaction contains a link or non-directory".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn finish_transfer(directory: &Path, result: Result<OperationsBackup>) -> Result<OperationsBackup> {
    match (result, remove_directory(directory)) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.with_recovery(Err(cleanup))),
    }
}

pub(super) fn receipt(metadata: &ArchiveMetadata) -> Result<OperationsBackup> {
    Ok(OperationsBackup {
        id: super::config::identifier(&metadata.id)?,
        instance: super::config::identifier(&metadata.instance_id)?,
        label: metadata
            .label
            .clone()
            .try_into()
            .map_err(|_| Error::Invalid("backup label is too long".into()))?,
        created_at: metadata
            .created_at
            .timestamp()
            .try_into()
            .map_err(|_| Error::Clock)?,
        bytes: metadata.compressed_size,
        expanded_bytes: metadata.original_size,
        files: metadata.file_count,
    })
}
fn recover_directory(transactions: &Path, instance: &str, root: &Path) -> Result<()> {
    let directory = transactions.join(instance);
    if !directory.try_exists()? {
        return Ok(());
    }
    let directory = super::fleet::directory(transactions, instance)?;
    let journal = directory.join(JOURNAL);
    if journal.try_exists()? {
        let metadata = std::fs::symlink_metadata(&journal)?;
        if !metadata.is_file() || metadata.len() > METADATA_BYTES {
            return Err(Error::Invalid("invalid restore journal".into()));
        }
        let journal: RestoreJournal = serde_json::from_slice(&std::fs::read(&journal)?)?;
        super::config::identifier(&journal.safety)?;
        if directory_identity(root)? != journal.previous {
            let candidate = directory.join(CANDIDATE);
            if directory_identity(&candidate)? != journal.previous {
                return Err(Error::Invalid(
                    "restore journal has lost its previous directory".into(),
                ));
            }
            exchange(root, &candidate)?;
            sync(&directory)?;
            sync(
                root.parent()
                    .ok_or_else(|| Error::Invalid("instance parent missing".into()))?,
            )?;
        }
    }
    if !root.try_exists()? {
        return Err(Error::Invalid(
            "restore recovery is missing the instance directory".into(),
        ));
    }
    remove_directory(&directory)?;
    sync(transactions)
}
impl Backups {
    pub fn new(data: &Path, settings: BackupSettings, jobs: Arc<Jobs>) -> Result<Self> {
        let base_dir = super::fleet::directory(data, "backups")?;
        let transactions = super::fleet::directory(data, "transactions")?;
        let transfer = super::fleet::directory(data, "transfers")?;
        // The supervisor data lease excludes a transfer from an earlier process.
        for entry in std::fs::read_dir(&transfer)? {
            remove_directory(&entry?.path())?;
        }
        let archives = ArchiveManager::new(ArchiveConfig {
            base_dir,
            algorithm: CompressionAlgorithm::TarGz,
            max_archives_per_instance: settings.retained,
            max_bytes_per_instance: settings.retained_bytes,
            limits: ArchiveLimits {
                bytes: settings.archive_bytes,
                entries: settings.entries,
            },
            ..Default::default()
        });
        Ok(Self {
            archives,
            transactions,
            transfer,
            settings,
            jobs,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(TRANSFER_TIMEOUT)
                .build()?,
        })
    }
    fn owns(&self, instance: &str, scope: &str, archive: &str) -> Result<()> {
        if !self.jobs.has_backup(instance, scope, archive)? {
            return Err(Error::NotFound);
        }
        Ok(())
    }
    pub async fn list(&self, instance: &str, scope: &str) -> Result<OperationsBackupPage> {
        let records = self.archives.list(instance).await?;
        let ids = records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let owned = self.jobs.backup_ids(instance, scope, &ids)?;
        let backups = records
            .iter()
            .rev()
            .filter(|record| owned.contains(&record.id))
            .map(receipt)
            .collect::<Result<Vec<_>>>()?;
        Ok(OperationsBackupPage { backups })
    }
    pub async fn create(
        &self,
        instance: &str,
        scope: &str,
        root: &Path,
        label: &str,
    ) -> Result<ArchiveMetadata> {
        self.reconcile(instance).await?;
        let request = ArchiveRequest::new(instance, label);
        self.jobs.reserve_backup(&request.id, instance, scope)?;
        let result = self
            .archives
            .create(
                &request,
                root,
                InstanceState::Stopped,
                &FullArchiveStrategy::new(),
            )
            .await
            .map_err(Error::from);
        let cleanup = self.reconcile(instance).await;
        match (result, cleanup) {
            (Ok(record), Ok(())) => Ok(record),
            (Err(error), cleanup) => Err(error.with_recovery(cleanup)),
            (Ok(_), Err(error)) => Err(error),
        }
    }
    pub async fn reconcile(&self, instance: &str) -> Result<()> {
        let retained = self
            .archives
            .list(instance)
            .await?
            .into_iter()
            .map(|metadata| metadata.id)
            .collect::<Vec<_>>();
        self.jobs.prune_backup_owners(instance, &retained)
    }
    pub async fn delete(
        &self,
        instance: &str,
        scope: &str,
        archive: &str,
    ) -> Result<OperationsBackup> {
        self.owns(instance, scope, archive)?;
        let record = self.archives.find_metadata(instance, archive).await?;
        self.archives.delete(instance, archive).await?;
        self.jobs.forget_backup(archive)?;
        receipt(&record)
    }
    pub async fn recover(&self, instance: &str, root: &Path) -> Result<()> {
        let transactions = self.transactions.clone();
        let instance = instance.to_owned();
        let root = root.to_path_buf();
        tokio::task::spawn_blocking(move || recover_directory(&transactions, &instance, &root))
            .await?
    }
    pub fn pending(&self, instance: &str) -> Result<bool> {
        Ok(self
            .transactions
            .join(instance)
            .join(JOURNAL)
            .try_exists()?)
    }
    pub async fn discard(&self, instance: &str) -> Result<()> {
        if self.pending(instance)? {
            return Err(Error::Invalid(
                "unfinished restore requires supervisor recovery".into(),
            ));
        }
        let transaction = self.transactions.join(instance);
        tokio::task::spawn_blocking(move || remove_directory(&transaction)).await?
    }
    pub async fn prepare(
        &self,
        instance: &str,
        scope: &str,
        archive: &str,
        root: &Path,
    ) -> Result<(ArchiveMetadata, PathBuf)> {
        self.owns(instance, scope, archive)?;
        let previous = self.transactions.join(instance);
        if previous.join(JOURNAL).try_exists()? {
            return Err(Error::Invalid(
                "an unfinished restore requires supervisor recovery".into(),
            ));
        }
        remove_directory(&previous)?;
        if !root.try_exists()? {
            return Err(Error::Invalid("instance directory missing".into()));
        }
        let metadata = self.archives.find_metadata(instance, archive).await?;
        let transaction = super::fleet::directory(&self.transactions, instance)?;
        let candidate = super::fleet::directory(&transaction, CANDIDATE)?;
        if let Err(error) = self.archives.restore(instance, archive, &candidate).await {
            return Err(Error::from(error).with_recovery(self.discard(instance).await));
        }
        Ok((metadata, transaction))
    }
    pub fn activate(&self, transaction: &Path, root: &Path, safety: &str) -> Result<()> {
        let journal = transaction.join(JOURNAL);
        let payload = serde_json::to_vec(&RestoreJournal {
            previous: directory_identity(root)?,
            safety: safety.into(),
        })?;
        let pending = transaction.join(PENDING_JOURNAL);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&pending)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(pending, journal)?;
        sync(transaction)?;
        exchange(root, &transaction.join(CANDIDATE))?;
        sync(transaction)?;
        sync(
            root.parent()
                .ok_or_else(|| Error::Invalid("instance parent missing".into()))?,
        )?;
        Ok(())
    }
    pub async fn commit(&self, transaction: &Path) -> Result<()> {
        let transaction = transaction.to_path_buf();
        let parent = self.transactions.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::remove_file(transaction.join(JOURNAL))?;
            sync(&transaction)?;
            remove_directory(&transaction)?;
            sync(&parent)
        })
        .await?
    }
    fn remote(&self, archive: &str) -> Result<(reqwest::Url, String)> {
        let remote =
            self.settings.remote.as_ref().ok_or_else(|| {
                Error::Invalid("encrypted backup storage is not configured".into())
            })?;
        let url = super::authority::endpoint(&remote.endpoint)?
            .join(&format!("backups/{archive}.age"))
            .map_err(|_| Error::Invalid("invalid backup object URL".into()))?;
        Ok((url, private_text(&remote.credential_file)?))
    }
    pub async fn export(
        &self,
        instance: &str,
        scope: &str,
        archive: &str,
        job: &str,
    ) -> Result<OperationsBackup> {
        self.owns(instance, scope, archive)?;
        let metadata = self.archives.find_metadata(instance, archive).await?;
        let input = self.archives.open_data(instance, archive).await?;
        let (url, credential) = self.remote(archive)?;
        let recipient = self
            .settings
            .remote
            .as_ref()
            .ok_or(Error::NotFound)?
            .recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|_| Error::Encryption("invalid recipient".into()))?;
        let directory = super::fleet::directory(&self.transfer, job)?;
        let result = async {
            let path = directory.join(ENCRYPTED_ARCHIVE);
            let encrypted = path.clone();
            let envelope = Envelope {
                scope: scope.into(),
                archive: metadata.clone(),
            };
            tokio::task::spawn_blocking(move || -> Result<()> {
                let output = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&encrypted)?;
                let header = serde_json::to_vec(&envelope)?;
                if header.len() as u64 > METADATA_BYTES {
                    return Err(Error::Invalid("backup metadata is too large".into()));
                }
                let encryptor = age::Encryptor::with_recipients(std::iter::once(
                    &recipient as &dyn age::Recipient,
                ))
                .map_err(|error| Error::Encryption(error.to_string()))?;
                let mut writer = encryptor.wrap_output(output)?;
                writer.write_all(
                    &u32::try_from(header.len())
                        .map_err(|_| Error::Invalid("backup metadata size".into()))?
                        .to_be_bytes(),
                )?;
                writer.write_all(&header)?;
                let mut input = input;
                std::io::copy(&mut input, &mut writer)?;
                writer.finish()?.sync_all()?;
                Ok(())
            })
            .await??;
            let file = tokio::fs::File::open(&path).await?;
            let response = self
                .client
                .put(url)
                .bearer_auth(credential)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header(
                    reqwest::header::CONTENT_LENGTH,
                    file.metadata().await?.len(),
                )
                .body(reqwest::Body::from(file))
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(Error::Invalid("encrypted backup upload failed".into()));
            }
            receipt(&metadata)
        }
        .await;
        finish_transfer(&directory, result)
    }
    pub async fn import(
        &self,
        instance: &str,
        scope: &str,
        archive: &str,
        job: &str,
    ) -> Result<OperationsBackup> {
        let (url, credential) = self.remote(archive)?;
        let identity_path = self
            .settings
            .remote
            .as_ref()
            .and_then(|remote| remote.identity_file.as_ref())
            .ok_or_else(|| {
                Error::Invalid("install the offline backup identity before recovery".into())
            })?;
        let identity = private_text(identity_path)?
            .parse::<age::x25519::Identity>()
            .map_err(|_| Error::Encryption("invalid recovery identity".into()))?;
        let directory = super::fleet::directory(&self.transfer, job)?;
        let result = async {
            let encrypted = directory.join(ENCRYPTED_ARCHIVE);
            let decrypted = directory.join("archive");
            let mut response = self.client.get(url).bearer_auth(credential).send().await?;
            if !response.status().is_success() {
                return Err(Error::Invalid("encrypted backup download failed".into()));
            }
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&encrypted)
                .await?;
            let limit = self
                .settings
                .archive_bytes
                .checked_add(self.settings.archive_bytes / ENCRYPTION_OVERHEAD_DIVISOR)
                .and_then(|bytes| bytes.checked_add(METADATA_BYTES * 2))
                .ok_or_else(|| Error::Invalid("backup transfer quota overflow".into()))?;
            let mut bytes = 0u64;
            while let Some(chunk) = response.chunk().await? {
                bytes = bytes
                    .checked_add(chunk.len() as u64)
                    .ok_or_else(|| Error::Invalid("backup transfer quota overflow".into()))?;
                if bytes > limit {
                    return Err(Error::Invalid("encrypted backup exceeds its quota".into()));
                }
                file.write_all(&chunk).await?;
            }
            file.sync_all().await?;
            drop(file);
            let import_scope = scope.to_owned();
            let instance = instance.to_owned();
            let archive = archive.to_owned();
            let source = decrypted.clone();
            let max = self.settings.archive_bytes;
            let metadata = tokio::task::spawn_blocking(move || -> Result<ArchiveMetadata> {
                let input = File::open(encrypted)?;
                let decryptor = age::Decryptor::new(input)
                    .map_err(|error| Error::Encryption(error.to_string()))?;
                let mut reader = decryptor
                    .decrypt(std::iter::once(&identity as &dyn age::Identity))
                    .map_err(|error| Error::Encryption(error.to_string()))?;
                let mut length = [0u8; 4];
                reader.read_exact(&mut length)?;
                let length = u64::from(u32::from_be_bytes(length));
                if length > METADATA_BYTES {
                    return Err(Error::Invalid("backup metadata is too large".into()));
                }
                let mut header = vec![
                    0u8;
                    usize::try_from(length).map_err(|_| Error::Invalid(
                        "backup metadata size".into()
                    ))?
                ];
                reader.read_exact(&mut header)?;
                let envelope: Envelope = serde_json::from_slice(&header)?;
                if envelope.scope != import_scope
                    || envelope.archive.instance_id != instance
                    || envelope.archive.id != archive
                    || envelope.archive.algorithm != CompressionAlgorithm::TarGz
                    || envelope.archive.scope != minecraftd::archive::metadata::ArchiveScope::Full
                    || envelope.archive.instance_state != InstanceState::Stopped
                {
                    return Err(Error::Invalid(
                        "backup belongs to another target or scope".into(),
                    ));
                }
                let mut output = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(source)?;
                let copied = std::io::copy(&mut (&mut reader).take(max), &mut output)?;
                let mut tail = [0u8; 1];
                if copied != envelope.archive.compressed_size || reader.read(&mut tail)? != 0 {
                    return Err(Error::Invalid(
                        "decrypted backup exceeds its declared size".into(),
                    ));
                }
                output.sync_all()?;
                Ok(envelope.archive)
            })
            .await??;
            receipt(&metadata)?;
            let instance = metadata.instance_id.clone();
            self.reconcile(&instance).await?;
            self.jobs.reserve_backup(&metadata.id, &instance, scope)?;
            let result = self
                .archives
                .import(metadata, &decrypted)
                .await
                .map_err(Error::from);
            let cleanup = self.reconcile(&instance).await;
            let metadata = match (result, cleanup) {
                (Ok(record), Ok(())) => record,
                (Err(error), cleanup) => return Err(error.with_recovery(cleanup)),
                (Ok(_), Err(error)) => return Err(error),
            };
            receipt(&metadata)
        }
        .await;
        finish_transfer(&directory, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interrupted_activation_restores_the_previous_directory_on_restart() -> Result<()> {
        let data = tempfile::tempdir()?;
        let root = data.path().join("world");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("data"), b"previous")?;
        let settings = BackupSettings {
            retained: 2,
            retained_bytes: 1024 * 1024,
            archive_bytes: 1024 * 1024,
            entries: 100,
            remote: None,
        };
        let jobs = Arc::new(Jobs::open(Path::new(":memory:"), 100)?);
        let backups = Backups::new(data.path(), settings.clone(), Arc::clone(&jobs))?;
        let transaction = super::super::fleet::directory(&backups.transactions, "world")?;
        let candidate = super::super::fleet::directory(&transaction, CANDIDATE)?;
        std::fs::write(candidate.join("data"), b"candidate")?;
        std::fs::write(transaction.join(PENDING_JOURNAL), b"{")?;
        drop(backups);
        let backups = Backups::new(data.path(), settings.clone(), Arc::clone(&jobs))?;
        backups.recover("world", &root).await?;
        assert_eq!(std::fs::read(root.join("data"))?, b"previous");
        let transaction = super::super::fleet::directory(&backups.transactions, "world")?;
        let candidate = super::super::fleet::directory(&transaction, CANDIDATE)?;
        std::fs::write(candidate.join("data"), b"candidate")?;
        backups.activate(&transaction, &root, "safety-archive")?;
        assert_eq!(std::fs::read(root.join("data"))?, b"candidate");
        drop(backups);
        let recovered = Backups::new(data.path(), settings, jobs)?;
        recovered.recover("world", &root).await?;
        assert_eq!(std::fs::read(root.join("data"))?, b"previous");
        assert!(!transaction.try_exists()?);
        Ok(())
    }
}
