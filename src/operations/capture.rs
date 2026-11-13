use super::{Error, Result, jobs::Jobs};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

const OUTPUT_QUEUE_RECORDS: usize = 128;
const OUTPUT_BATCH_RECORDS: usize = 64;
pub(super) struct Health {
    pub failed: AtomicBool,
    pub lost: AtomicBool,
}
impl Health {
    pub fn new(lost: bool) -> Self {
        Self {
            failed: AtomicBool::new(false),
            lost: AtomicBool::new(lost),
        }
    }
}
pub(super) struct Output {
    pub instance: String,
    pub data: Vec<u8>,
    pub at: u64,
    pub health: Arc<Health>,
}
enum Message {
    Output(Output),
    Finish,
}
pub(super) struct Capture {
    sender: mpsc::Sender<Message>,
    task: Mutex<Option<JoinHandle<Result<()>>>>,
}
impl Capture {
    pub fn start(jobs: Arc<Jobs>) -> Arc<Self> {
        let (sender, mut receiver) = mpsc::channel(OUTPUT_QUEUE_RECORDS);
        let task = tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                let Message::Output(output) = message else {
                    receiver.close();
                    continue;
                };
                let mut batch = vec![output];
                while batch.len() < OUTPUT_BATCH_RECORDS {
                    match receiver.try_recv() {
                        Ok(Message::Output(output)) => batch.push(output),
                        Ok(Message::Finish) => {
                            receiver.close();
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let store = Arc::clone(&jobs);
                let (batch, result) = tokio::task::spawn_blocking(move || {
                    let result = store.append_output(&batch);
                    (batch, result)
                })
                .await?;
                for output in batch {
                    match &result {
                        Ok(()) => {
                            if output.health.failed.swap(false, Ordering::SeqCst) {
                                tracing::info!(instance=%output.instance,"managed output capture recovered");
                            }
                        }
                        Err(error) => {
                            output.health.lost.store(true, Ordering::SeqCst);
                            if !output.health.failed.swap(true, Ordering::SeqCst) {
                                tracing::error!(instance=%output.instance,%error,"managed output capture failed");
                            }
                        }
                    }
                }
            }
            Ok(())
        });
        Arc::new(Self {
            sender,
            task: Mutex::new(Some(task)),
        })
    }
    pub fn submit(&self, instance: &str, data: &[u8], at: u64, health: &Arc<Health>) {
        let record = Output {
            instance: instance.into(),
            data: data.into(),
            at,
            health: Arc::clone(health),
        };
        if let Err(error) = self.sender.try_send(Message::Output(record)) {
            health.lost.store(true, Ordering::SeqCst);
            if matches!(error, mpsc::error::TrySendError::Closed(_)) {
                health.failed.store(true, Ordering::SeqCst);
            }
        }
    }
    pub async fn finish(&self) -> Result<()> {
        let Some(task) = self.task.lock().await.take() else {
            return Ok(());
        };
        let sent = self.sender.send(Message::Finish).await;
        task.await??;
        sent.map_err(|_| Error::StorageUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closing_capture_drains_output_accepted_after_finish_was_enqueued() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let jobs = Arc::new(Jobs::open(&directory.path().join("jobs.sqlite"), 100)?);
        let capture = Capture::start(Arc::clone(&jobs));
        capture
            .sender
            .try_send(Message::Finish)
            .map_err(|_| Error::StorageUnavailable)?;
        let health = Arc::new(Health::new(false));
        capture.submit("world", b"final output", 100, &health);
        capture.finish().await?;
        assert_eq!(jobs.output("world", 0, 1)?.entries[0].data, "final output");
        assert!(!health.lost.load(Ordering::SeqCst));
        Ok(())
    }
    #[tokio::test]
    async fn saturated_capture_keeps_producers_running_and_records_the_gap() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let jobs = Arc::new(Jobs::open(&directory.path().join("jobs.sqlite"), 100)?);
        let capture = Capture::start(Arc::clone(&jobs));
        let health = Arc::new(Health::new(false));
        for _ in 0..=OUTPUT_QUEUE_RECORDS {
            capture.submit("world", b"output", 100, &health);
        }
        assert!(health.lost.load(Ordering::SeqCst));
        capture.finish().await?;
        let output = jobs.output("world", 0, 1)?;
        assert!(output.truncated);
        assert_eq!(output.entries.len(), 1);
        assert!(!health.failed.load(Ordering::SeqCst));
        Ok(())
    }
}
