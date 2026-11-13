use super::{Error, Result, capture::Output};
use crate::operation_contracts::{
    OPERATIONS_MAX_PAGE_ROWS, OPERATIONS_MAX_REQUEST_BYTES, OperationsActor, OperationsCursor,
    OperationsHumanApproval, OperationsIntent, OperationsJob, OperationsJobPage,
    OperationsJobState, OperationsLogPage, OperationsLogRecord,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::atomic::Ordering;
use std::{path::Path, sync::Mutex, time::Duration};

const MAX_LOG_RECORDS: i64 = 512;

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
        database.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, body TEXT NOT NULL CHECK(json_valid(body))); CREATE TABLE IF NOT EXISTS logs(sequence INTEGER PRIMARY KEY AUTOINCREMENT,instance TEXT NOT NULL,at INTEGER NOT NULL,data TEXT NOT NULL,clipped INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS logs_instance_sequence ON logs(instance,sequence); CREATE TABLE IF NOT EXISTS log_retention(instance TEXT PRIMARY KEY,pruned INTEGER NOT NULL,incomplete INTEGER NOT NULL);")?;
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
        approval: Option<OperationsHumanApproval>,
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
            if serde_json::to_value(&previous.intent)? != serde_json::to_value(&intent)?
                || serde_json::to_value(&previous.approval)? != serde_json::to_value(&approval)?
            {
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
            approval,
            state: OperationsJobState::Queued,
            created_at: at,
            updated_at: at,
            error: None,
            expires_at,
            cancelled_by: None,
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

    pub fn cancel(&self, id: &str, actor: OperationsActor, at: u64) -> Result<OperationsJob> {
        self.change(id, |job| {
            if matches!(job.state, OperationsJobState::Cancelled) {
                return Ok(job.clone());
            }
            advance(
                job,
                OperationsJobState::Cancelled,
                at,
                Some("cancelled by an administrator before execution".into()),
            )?;
            job.cancelled_by = Some(actor);
            Ok(job.clone())
        })
    }

    pub fn history(
        &self,
        instance: &str,
        scope: &str,
        before: i64,
        limit: usize,
    ) -> Result<OperationsJobPage> {
        let rows = {
            let database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
            let mut query = database.prepare("SELECT rowid,body FROM jobs WHERE rowid<? AND json_extract(body,'$.intent.command.instance')=? AND json_extract(body,'$.intent.scope')=? ORDER BY rowid DESC LIMIT ?")?;
            query
                .query_map(
                    params![
                        before,
                        instance,
                        scope,
                        sql_count(limit.min(OPERATIONS_MAX_PAGE_ROWS))?
                    ],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut ids = Vec::new();
        let mut page = OperationsJobPage {
            jobs: Vec::new(),
            cursor: None,
        };
        for (id, body) in rows {
            ids.push(id);
            page.jobs.push(serde_json::from_str(&body)?);
        }
        loop {
            page.cursor = ids.last().copied().map(cursor).transpose()?;
            if serde_json::to_vec(&page)?.len() <= OPERATIONS_MAX_REQUEST_BYTES {
                break;
            }
            page.jobs.pop();
            ids.pop();
        }
        Ok(page)
    }

    pub fn capture_lost(&self, instance: &str) -> Result<bool> {
        let database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
        Ok(database
            .query_row(
                "SELECT incomplete FROM log_retention WHERE instance=?",
                [instance],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(false))
    }
    pub fn append_output(&self, records: &[Output]) -> Result<()> {
        let mut database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
        let transaction = database.transaction()?;
        let mut instances = std::collections::BTreeSet::new();
        for record in records {
            let mut data = String::from_utf8_lossy(&record.data).into_owned();
            let mut end = data
                .len()
                .min(minecraftd::core::process::OUTPUT_SEGMENT_BYTES);
            while !data.is_char_boundary(end) {
                end -= 1;
            }
            let clipped = end < data.len();
            data.truncate(end);
            transaction.execute(
                "INSERT INTO logs(instance,at,data,clipped) VALUES(?,?,?,?)",
                params![
                    record.instance,
                    i64::try_from(record.at).map_err(|_| Error::Clock)?,
                    data,
                    clipped
                ],
            )?;
            transaction.execute("INSERT INTO log_retention VALUES(?,0,?) ON CONFLICT(instance) DO UPDATE SET incomplete=MAX(incomplete,excluded.incomplete)",params![record.instance,record.health.lost.load(Ordering::SeqCst)])?;
            instances.insert(&record.instance);
        }
        for instance in instances {
            let cutoff:Option<i64>=transaction.query_row("SELECT sequence FROM logs WHERE instance=? ORDER BY sequence DESC LIMIT 1 OFFSET ?",params![instance,MAX_LOG_RECORDS],|row|row.get(0)).optional()?;
            if let Some(cutoff) = cutoff {
                transaction.execute(
                    "UPDATE log_retention SET pruned=MAX(pruned,?) WHERE instance=?",
                    params![cutoff, instance],
                )?;
                transaction.execute(
                    "DELETE FROM logs WHERE instance=? AND sequence<=?",
                    params![instance, cutoff],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn output(&self, instance: &str, after: i64, limit: usize) -> Result<OperationsLogPage> {
        let (pruned, incomplete, rows) = {
            let database = self.0.lock().map_err(|_| Error::StorageUnavailable)?;
            let (pruned, incomplete): (i64, bool) = database
                .query_row(
                    "SELECT pruned,incomplete FROM log_retention WHERE instance=?",
                    [instance],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .unwrap_or((0, false));
            let mut query = database.prepare("SELECT sequence,at,data,clipped FROM logs WHERE instance=? AND sequence>? ORDER BY sequence LIMIT ?")?;
            let rows = query
                .query_map(
                    params![
                        instance,
                        after.max(pruned),
                        sql_count(limit.min(OPERATIONS_MAX_PAGE_ROWS))?
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            (pruned, incomplete, rows)
        };
        let start = after.max(pruned);
        let mut page = OperationsLogPage {
            entries: Vec::new(),
            cursor: cursor(start)?,
            truncated: after < pruned || incomplete,
        };
        for (sequence, at, data, clipped) in rows {
            page.entries.push(OperationsLogRecord {
                sequence: cursor(sequence)?,
                at: u64::try_from(at).map_err(|_| Error::Clock)?,
                data,
                clipped,
            });
        }
        loop {
            page.cursor = page
                .entries
                .last()
                .map(|entry| entry.sequence.clone())
                .unwrap_or(cursor(start)?);
            if serde_json::to_vec(&page)?.len() <= OPERATIONS_MAX_REQUEST_BYTES {
                break;
            }
            page.entries.pop();
        }
        Ok(page)
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

fn sql_count(value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Invalid("page size exceeds storage range".into()))
}

fn cursor(value: i64) -> Result<OperationsCursor> {
    value
        .to_string()
        .try_into()
        .map_err(|_| Error::Invalid("invalid operations cursor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_output_advances_cursors_within_the_wire_byte_budget() -> Result<()> {
        let jobs = Jobs::open(Path::new(":memory:"), 100)?;
        let data = vec![0; minecraftd::core::process::OUTPUT_SEGMENT_BYTES];
        for _ in 0..MAX_LOG_RECORDS + 2 {
            jobs.append_output(&[Output {
                instance: "world".into(),
                data: data.clone(),
                at: 100,
                health: std::sync::Arc::new(super::super::capture::Health::new(false)),
            }])?;
        }
        let page = jobs.output("world", 0, OPERATIONS_MAX_PAGE_ROWS)?;
        assert!(page.truncated);
        assert_eq!(page.entries.len(), 1);
        assert!(serde_json::to_vec(&page)?.len() <= OPERATIONS_MAX_REQUEST_BYTES);
        let cursor = page
            .cursor
            .to_string()
            .parse::<i64>()
            .map_err(|_| Error::Invalid("test cursor".into()))?;
        let next = jobs.output("world", cursor, OPERATIONS_MAX_PAGE_ROWS)?;
        assert!(!next.truncated);
        assert_ne!(page.cursor.to_string(), next.cursor.to_string());
        Ok(())
    }

    #[test]
    fn queued_retry_renews_the_stored_lease_before_atomic_execution_admission() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let jobs = Jobs::open(&directory.path().join("jobs.sqlite"), 100)?;
        let intent: OperationsIntent = serde_json::from_value(serde_json::json!({
            "id":"queued-job", "actor":{"account":"administrator","client":null,"request":"original-call"},
            "scope":"global", "command":{"instance":"gateway","operation":{"action":"start"}}
        }))?;
        let (_, fresh) = jobs.submit(intent.clone(), None, 105, 100)?;
        assert!(fresh);
        let (renewed, fresh) = jobs.submit(intent, None, 110, 104)?;
        assert!(!fresh);
        assert_eq!(renewed.expires_at, 110);
        let started = jobs
            .begin("queued-job", 106, false)?
            .ok_or_else(|| Error::Invalid("renewed job was not admitted".into()))?;
        assert!(matches!(started.state, OperationsJobState::Running));
        assert_eq!(started.intent.actor.request, "original-call");
        let mut pending = started.intent.clone();
        pending.id = "cancelled-job"
            .parse()
            .map_err(|_| Error::Invalid("test job ID".into()))?;
        jobs.submit(pending.clone(), None, 110, 106)?;
        let cancelled = jobs.cancel("cancelled-job", pending.actor, 107)?;
        assert!(matches!(cancelled.state, OperationsJobState::Cancelled));
        assert!(cancelled.cancelled_by.is_some());
        assert!(jobs.begin("cancelled-job", 108, false)?.is_none());
        Ok(())
    }
}
