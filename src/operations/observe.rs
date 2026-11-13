use super::{Error, Result, now};
use crate::operation_contracts::{
    OperationsAlert, OperationsInstanceState, OperationsObservation, OperationsSnapshot,
};
use std::{collections::HashMap, path::Path, sync::Mutex, time::Instant};
use sysinfo::{Disks, MINIMUM_CPU_UPDATE_INTERVAL, Pid, ProcessesToUpdate, System};

const PERCENT_SCALE: u64 = 100;
const MIN_FREE_PERCENT: u64 = 10;
struct Samples {
    system: System,
    disks: Disks,
    refreshed: Option<Instant>,
    processes: HashMap<Pid, (u64, Option<f64>)>,
}
pub(super) struct Observer {
    started: Instant,
    samples: Mutex<Samples>,
}
impl Observer {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            samples: Mutex::new(Samples {
                system: System::new(),
                disks: Disks::new(),
                refreshed: None,
                processes: HashMap::new(),
            }),
        }
    }
    pub fn observe(
        &self,
        root: &Path,
        snapshot: OperationsSnapshot,
        instance: &str,
        expected: bool,
        logs_failed: bool,
        logs_lost: bool,
    ) -> Result<OperationsObservation> {
        let selected = snapshot
            .instances
            .iter()
            .find(|item| item.id.to_string() == instance)
            .cloned()
            .ok_or(Error::NotFound)?;
        let pids: Vec<Pid> = snapshot
            .instances
            .iter()
            .filter_map(|item| {
                item.pid
                    .and_then(|pid| u32::try_from(pid).ok())
                    .map(Pid::from_u32)
            })
            .collect();
        let mut samples = self.samples.lock().map_err(|_| Error::StorageUnavailable)?;
        let at = Instant::now();
        if samples
            .refreshed
            .is_none_or(|last| at.duration_since(last) >= MINIMUM_CPU_UPDATE_INTERVAL)
        {
            samples
                .system
                .refresh_processes(ProcessesToUpdate::Some(&pids), true);
            let mut processes = HashMap::new();
            for pid in pids {
                if let Some(process) = samples.system.process(pid) {
                    let ready = samples
                        .processes
                        .get(&pid)
                        .is_some_and(|(started, _)| *started == process.start_time());
                    processes.insert(
                        pid,
                        (
                            process.start_time(),
                            ready.then(|| f64::from(process.cpu_usage())),
                        ),
                    );
                }
            }
            samples.processes = processes;
            samples.refreshed = Some(at);
        }
        samples.system.refresh_memory();
        samples.disks.refresh(true);
        let disk = samples
            .disks
            .list()
            .iter()
            .filter(|disk| root.starts_with(disk.mount_point()))
            .max_by_key(|disk| disk.mount_point().components().count())
            .ok_or_else(|| Error::Invalid("managed storage volume is unavailable".into()))?;
        let disk_total_bytes = disk.total_space();
        let disk_available_bytes = disk.available_space();
        let pid = selected
            .pid
            .and_then(|pid| u32::try_from(pid).ok())
            .map(Pid::from_u32);
        let cpu_percent = pid.and_then(|pid| samples.processes.get(&pid).and_then(|(_, cpu)| *cpu));
        let memory_bytes =
            pid.and_then(|pid| samples.system.process(pid).map(|process| process.memory()));
        let mut alerts = Vec::new();
        if matches!(selected.state, OperationsInstanceState::Error) {
            alerts.push(OperationsAlert::ProcessError);
        }
        if expected
            && (matches!(selected.state, OperationsInstanceState::Stopped)
                || matches!(
                    selected.state,
                    OperationsInstanceState::Running
                        | OperationsInstanceState::Starting
                        | OperationsInstanceState::Error
                ) && memory_bytes.is_none())
        {
            alerts.push(OperationsAlert::ProcessStopped);
        }
        if logs_failed {
            alerts.push(OperationsAlert::LogStorageFailed);
        }
        if logs_lost {
            alerts.push(OperationsAlert::LogCaptureLoss);
        }
        if disk_available_bytes.saturating_mul(PERCENT_SCALE)
            < disk_total_bytes.saturating_mul(MIN_FREE_PERCENT)
        {
            alerts.push(OperationsAlert::DiskPressure);
        }
        if samples
            .system
            .available_memory()
            .saturating_mul(PERCENT_SCALE)
            < samples
                .system
                .total_memory()
                .saturating_mul(MIN_FREE_PERCENT)
        {
            alerts.push(OperationsAlert::MemoryPressure);
        }
        Ok(OperationsObservation {
            observed_at: now()?,
            uptime_seconds: self.started.elapsed().as_secs(),
            instance: selected,
            cpu_percent,
            memory_bytes,
            disk_total_bytes,
            disk_available_bytes,
            alerts,
        })
    }
}
