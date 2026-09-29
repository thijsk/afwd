use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use hickory_resolver::proto::rr::{IntoName, RData, RecordType};
use hickory_resolver::{
    config::ResolverConfig, name_server::TokioConnectionProvider, TokioResolver,
};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::config::{parse_txt_record, ConfigError, ForwardingConfig};

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("DNS lookup failed")]
    Dns(#[from] hickory_resolver::ResolveError),
    #[error("AFWD configuration is invalid")]
    Config(#[from] ConfigError),
    #[error("no AFWD TXT record found")]
    NotFound,
}

#[derive(Clone)]
pub struct DnsConfig {
    resolver: TokioResolver,
    cache: Arc<RwLock<HashMap<String, (Instant, ForwardingConfig)>>>,
    ttl: Duration,
}

impl DnsConfig {
    pub fn new(ttl: Duration) -> Self {
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        Self {
            resolver,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub async fn resolve(&self, host: &str) -> Result<ForwardingConfig, ResolveError> {
        if let Some((expires, result)) = self.cache.read().await.get(host) {
            if *expires > Instant::now() {
                return Ok(result.clone());
            }
        }

        let result = self.lookup(host).await;
        if let Ok(config) = &result {
            self.cache
                .write()
                .await
                .insert(host.to_owned(), (Instant::now() + self.ttl, config.clone()));
        }
        result
    }

    async fn lookup(&self, host: &str) -> Result<ForwardingConfig, ResolveError> {
        if let Some(config) = self.lookup_txt(host).await? {
            return Ok(config);
        }

        let aliases = self.resolver.lookup(host, RecordType::CNAME).await?;
        for record in aliases.iter() {
            if let RData::CNAME(target) = record {
                if let Some(config) = self.lookup_txt(target.0.clone()).await? {
                    return Ok(config);
                }
            }
        }
        Err(ResolveError::NotFound)
    }

    async fn lookup_txt<N: IntoName>(
        &self,
        host: N,
    ) -> Result<Option<ForwardingConfig>, ResolveError> {
        let records = self.resolver.txt_lookup(host).await?;
        for record in records.iter() {
            let bytes = record
                .txt_data()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if text.starts_with("v=afwd1") {
                    return Ok(Some(parse_txt_record(text)?));
                }
            }
        }
        Ok(None)
    }
}
