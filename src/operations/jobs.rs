use super::{Error, Result};
use crate::operation_contracts::{OperationsIntent, OperationsJob, OperationsJobState};
use rusqlite::{Connection, OptionalExtension, params};
use std::{path::Path, sync::Mutex, time::Duration};

const DATABASE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) struct Jobs(Mutex<Connection>);

fn advance(
    job: &mut OperationsJob,
    next: OperationsJobState,
    at: u64,
    error: Option<String>,
) -> Result<()> {
    if !matches!(
        (&job.state, &next),
        (
            OperationsJobState::Queued,
            OperationsJobState::Running
                | OperationsJobState::Cancelled
                | OperationsJobState::Interrupted
        ) | (
            OperationsJobState::Running,
            OperationsJobState::Succeeded
                | OperationsJobState::Failed
                | OperationsJobState::Interrupted
        )
    ) {
        return Err(Error::Conflict);
    }
    job.state = next;
    job.updated_at = at;
    job.error = error;
    Ok(())
}

impl Jobs {
    pub fn open(path: &Path, at: u64) -> Result<Self> {
        let database = Connection::open(path)?;
        database.busy_timeout(DATABASE_TIMEOUT)?;
        database.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, body TEXT NOT NULL CHECK(json_valid(body)));")?;
        let jobs = Self(Mutex::new(database));
        let pending = {
            let database = jobs.0.lock().map_err(|_| Error::StorageUnavailable)?;
            let mut statement = database.prepare("SELECT body FROM jobs WHERE json_extract(body,'$.state') IN (json_extract(?,'$'),json_extract(?,'$'))")?;
            statement
                .query_map(
                    params![
                        serde_json::to_string(&OperationsJobState::Queued)?,
                        serde_json::to_string(&OperationsJobState::Running)?
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for body in pending {
            let job: OperationsJob = serde_json::from_str(&body)?;
            jobs.transition(
                &job.intent.id.to_string(),
                OperationsJobState::Interrupted,
                at,
                Some("supervisor restarted during the operation".into()),
            )?;
        }
        Ok(jobs)
    }

    pub fn get(&self, id: &str) -> Result<Option<OperationsJob>> {
        let database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
        let body: Option<String> = database
            .query_row("SELECT body FROM jobs WHERE id=?", [id], |row| row.get(0))
            .optional()?;
        body.map(|body| serde_json::from_str(&body))
            .transpose()
            .map_err(Error::from)
    }

    pub fn submit(
        &self,
        intent: OperationsIntent,
        expires_at: u64,
        at: u64,
    ) -> Result<(OperationsJob, bool)> {
        let mut database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
        let transaction = database.transaction()?;
        let id = intent.id.to_string();
        let previous: Option<String> = transaction
            .query_row("SELECT body FROM jobs WHERE id=?", [&id], |row| row.get(0))
            .optional()?;
        if let Some(body) = previous {
            let mut previous: OperationsJob = serde_json::from_str(&body)?;
            if serde_json::to_value(&previous.intent)? != serde_json::to_value(&intent)? {
                return Err(Error::Conflict);
            }
            if matches!(previous.state, OperationsJobState::Queued)
                && expires_at > previous.expires_at
            {
                previous.expires_at = expires_at;
                previous.updated_at = at;
                transaction.execute(
                    "UPDATE jobs SET body=? WHERE id=?",
                    params![serde_json::to_string(&previous)?, id],
                )?;
            }
            transaction.commit()?;
            return Ok((previous, false));
        }
        let job = OperationsJob {
            intent,
            state: OperationsJobState::Queued,
            created_at: at,
            updated_at: at,
            error: None,
            expires_at,
        };
        transaction.execute(
            "INSERT INTO jobs VALUES(?,?)",
            params![id, serde_json::to_string(&job)?],
        )?;
        transaction.commit()?;
        Ok((job, true))
    }

    fn change<T>(
        &self,
        id: &str,
        update: impl FnOnce(&mut OperationsJob) -> Result<T>,
    ) -> Result<T> {
        let mut database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
        let transaction = database.transaction()?;
        let body: String =
            transaction.query_row("SELECT body FROM jobs WHERE id=?", [id], |row| row.get(0))?;
        let mut job: OperationsJob = serde_json::from_str(&body)?;
        let result = update(&mut job)?;
        transaction.execute(
            "UPDATE jobs SET body=? WHERE id=?",
            params![serde_json::to_string(&job)?, id],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn begin(&self, id: &str, at: u64, closing: bool) -> Result<Option<OperationsJob>> {
        self.change(id, |job| {
            if !matches!(job.state, OperationsJobState::Queued) {
                return Ok(None);
            }
            let active = at < job.expires_at && !closing;
            let (next, error) = if active {
                (OperationsJobState::Running, None)
            } else {
                (
                    OperationsJobState::Cancelled,
                    Some("authorization expired or supervisor stopped before execution".into()),
                )
            };
            advance(job, next, at, error)?;
            Ok(active.then(|| job.clone()))
        })
    }

    pub fn transition(
        &self,
        id: &str,
        next: OperationsJobState,
        at: u64,
        error: Option<String>,
    ) -> Result<OperationsJob> {
        self.change(id, |job| {
            advance(job, next, at, error)?;
            Ok(job.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_retry_renews_the_stored_lease_before_atomic_execution_admission() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let jobs = Jobs::open(&directory.path().join("jobs.sqlite"), 100)?;
        let intent: OperationsIntent = serde_json::from_value(serde_json::json!({
            "id":"queued-job", "actor":{"account":"administrator","client":null,"request":"original-call"},
            "scope":"global", "command":{"instance":"gateway","action":"start"}
        }))?;
        let (_, fresh) = jobs.submit(intent.clone(), 105, 100)?;
        assert!(fresh);
        let (renewed, fresh) = jobs.submit(intent, 110, 104)?;
        assert!(!fresh);
        assert_eq!(renewed.expires_at, 110);
        let started = jobs
            .begin("queued-job", 106, false)?
            .ok_or_else(|| Error::Invalid("renewed job was not admitted".into()))?;
        assert!(matches!(started.state, OperationsJobState::Running));
        assert_eq!(started.intent.actor.request, "original-call");
        Ok(())
    }
}
