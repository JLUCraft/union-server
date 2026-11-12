//! Owned listeners with coordinated shutdown and completion notification.
use anyhow::{Result, bail};
use std::{future::Future, net::SocketAddr, time::Duration};
use tokio::sync::{oneshot, watch};
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Service {
    name: &'static str,
    address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    completion: watch::Receiver<()>,
}
impl Service {
    pub(crate) fn spawn<F: Future<Output = Result<()>> + Send + 'static>(
        name: &'static str,
        address: SocketAddr,
        serve: impl FnOnce(oneshot::Receiver<()>) -> F,
    ) -> Self {
        let (stop, stopping) = oneshot::channel();
        let (completed, completion) = watch::channel(());
        let future = serve(stopping);
        let task = tokio::spawn(async move {
            let _completed = completed;
            let result = future.await;
            if let Err(error) = &result {
                tracing::error!(service = name, %error, "service stopped");
            }
            result
        });
        Self {
            name,
            address,
            stop: Some(stop),
            task: Some(task),
            completion,
        }
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub async fn closed(&self) {
        let mut completion = self.completion.clone();
        let _ = completion.changed().await;
    }
    pub async fn stop(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task).await {
                Ok(result) => result??,
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    bail!("{} shutdown timed out", self.name);
                }
            }
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
