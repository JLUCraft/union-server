//! Central game host assembly and listener ownership.
use crate::{Error, Result, Service, activity, native, scoring};
use anyhow::{Context, ensure};
use futures::{StreamExt, stream::FuturesUnordered};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    path::{Path, PathBuf},
};
const CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub services: Services,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Services {
    pub league_proxy: Option<LeagueProxy>,
    pub scoring: Option<scoring::Config>,
    pub activity_oracle: Option<activity::Config>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeagueProxy {
    pub config: native::Config,
}
fn relative(base: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path).map_err(Error::Configuration)
    }
    fn load_inner(path: &Path) -> anyhow::Result<Self> {
        let path = path.canonicalize()?;
        let base = path.parent().context("configuration directory missing")?;
        ensure!(
            std::fs::metadata(&path)?.len() <= CONFIG_BYTES,
            "configuration file too large"
        );
        let mut config: Self = serde_json::from_slice(&std::fs::read(&path)?)?;
        if let Some(proxy) = &mut config.services.league_proxy {
            relative(base, &mut proxy.config.session_token);
            relative(base, &mut proxy.config.waiting.forwarding_secret);
            relative(base, &mut proxy.config.arena.forwarding_secret);
        }
        if let Some(scoring) = &mut config.services.scoring {
            relative(base, &mut scoring.session_token);
            relative(base, &mut scoring.token);
        }
        if let Some(oracle) = &mut config.services.activity_oracle {
            relative(base, &mut oracle.session_token);
            relative(base, &mut oracle.spool);
            for probe in &mut oracle.probes {
                relative(base, &mut probe.token);
            }
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_inner().map_err(Error::Configuration)
    }
    fn validate_inner(&self) -> anyhow::Result<()> {
        let mut bindings = HashSet::new();
        let mut count = 0;
        let mut register = |address: SocketAddr| -> anyhow::Result<()> {
            count += 1;
            ensure!(
                address.port() == 0 || bindings.insert(address),
                "duplicate listener address"
            );
            Ok(())
        };
        if let Some(proxy) = &self.services.league_proxy {
            proxy.config.validate()?;
            register(proxy.config.bind)?;
        }
        if let Some(scoring) = &self.services.scoring {
            ensure!(
                scoring.bind.ip().is_loopback(),
                "scoring adapter must bind loopback"
            );
            register(scoring.bind)?;
        }
        if let Some(oracle) = &self.services.activity_oracle {
            ensure!(
                oracle.bind.ip().is_loopback(),
                "activity adapter must bind loopback"
            );
            register(oracle.bind)?;
        }
        ensure!(count > 0, "configure at least one game service");
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Status {
    pub services: BTreeMap<&'static str, SocketAddr>,
}
pub struct Host {
    services: Vec<Service>,
}
impl Host {
    pub async fn start(config: Config) -> Result<Self> {
        config.validate()?;
        let mut host = Self {
            services: Vec::new(),
        };
        if let Err(error) = host.prepare(config.services).await {
            let _ = host.shutdown().await;
            return Err(error);
        }
        Ok(host)
    }
    async fn prepare(&mut self, services: Services) -> Result<()> {
        let witnesses = activity::Witnesses::default();
        if let Some(proxy) = services.league_proxy {
            self.services.push(
                native::start(proxy.config, witnesses.clone())
                    .await
                    .map_err(|source| Error::Service {
                        service: "league_proxy",
                        source,
                    })?,
            );
        }
        if let Some(config) = services.scoring {
            self.services.push(
                scoring::start(config)
                    .await
                    .map_err(|source| Error::Service {
                        service: "scoring",
                        source,
                    })?,
            );
        }
        if let Some(config) = services.activity_oracle {
            self.services
                .push(activity::start(config, witnesses).await.map_err(|source| {
                    Error::Service {
                        service: "activity_oracle",
                        source,
                    }
                })?);
        }
        Ok(())
    }
    pub fn status(&self) -> Status {
        Status {
            services: self
                .services
                .iter()
                .map(|service| (service.name(), service.address()))
                .collect(),
        }
    }
    pub async fn run(&self) -> Result<()> {
        let mut completed: FuturesUnordered<_> = self
            .services
            .iter()
            .map(|service| async {
                service.closed().await;
                service.name()
            })
            .collect();
        let name = completed
            .next()
            .await
            .ok_or(Error::ServiceStopped("host"))?;
        Err(Error::ServiceStopped(name))
    }
    async fn shutdown(&mut self) -> Result<()> {
        let mut failure = None;
        for service in self.services.drain(..) {
            let name = service.name();
            if let Err(source) = service.stop().await {
                failure.get_or_insert(Error::Service {
                    service: name,
                    source,
                });
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub async fn close(mut self) -> Result<()> {
        self.shutdown().await
    }
}
