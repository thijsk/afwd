use std::{net::IpAddr, time::Duration};

use hickory_resolver::proto::rr::{IntoName, RData, RecordType};
use hickory_resolver::{
    config::ResolverConfig, name_server::TokioConnectionProvider, TokioResolver,
};
use thiserror::Error;

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
}

impl DnsConfig {
    /// Answers are cached for the record TTL, but never longer than `max_ttl`.
    pub fn new(max_ttl: Duration) -> Self {
        let mut builder = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        );
        let options = builder.options_mut();
        options.cache_size = 4096;
        options.positive_max_ttl = Some(max_ttl);
        options.negative_max_ttl = Some(max_ttl);
        Self {
            resolver: builder.build(),
        }
    }

    pub async fn resolve(&self, host: &str) -> Result<ForwardingConfig, ResolveError> {
        let text = self
            .find_record(host)
            .await?
            .ok_or(ResolveError::NotFound)?;
        Ok(parse_txt_record(&text)?)
    }

    /// The raw `v=afwd1` TXT record for `host`, or for the target of its CNAME.
    pub async fn find_record(
        &self,
        host: &str,
    ) -> Result<Option<String>, hickory_resolver::ResolveError> {
        if let Some(text) = self.lookup_txt(host).await? {
            return Ok(Some(text));
        }

        let Some(aliases) = found(self.resolver.lookup(host, RecordType::CNAME).await)? else {
            return Ok(None);
        };
        for record in aliases.iter() {
            if let RData::CNAME(target) = record {
                if let Some(text) = self.lookup_txt(target.0.clone()).await? {
                    return Ok(Some(text));
                }
            }
        }
        Ok(None)
    }

    /// The A and AAAA addresses of `host`, following CNAMEs.
    pub async fn addresses(
        &self,
        host: &str,
    ) -> Result<Vec<IpAddr>, hickory_resolver::ResolveError> {
        Ok(found(self.resolver.lookup_ip(host).await)?
            .map(|lookup| lookup.iter().collect())
            .unwrap_or_default())
    }

    /// SHA-256 hex hashes of stats tokens from `_afwd-stats.<host>` TXT records.
    pub async fn stats_hashes(&self, host: &str) -> Vec<String> {
        let Ok(records) = self
            .resolver
            .txt_lookup(format!("_afwd-stats.{host}."))
            .await
        else {
            return Vec::new();
        };
        records
            .iter()
            .map(|record| {
                record
                    .txt_data()
                    .iter()
                    .map(|chunk| String::from_utf8_lossy(chunk))
                    .collect::<String>()
            })
            .filter(|text| text.starts_with("v=afwdstats1"))
            .flat_map(|text| {
                text.split_whitespace()
                    .filter_map(|token| token.strip_prefix("h="))
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    async fn lookup_txt<N: IntoName>(
        &self,
        host: N,
    ) -> Result<Option<String>, hickory_resolver::ResolveError> {
        let Some(records) = found(self.resolver.txt_lookup(host).await)? else {
            return Ok(None);
        };
        Ok(records.iter().find_map(|record| {
            let bytes = record
                .txt_data()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            String::from_utf8(bytes)
                .ok()
                .filter(|text| text.starts_with("v=afwd1"))
        }))
    }
}

/// An answer saying the name or record type does not exist is not a DNS failure:
/// it means there is no AFWD record here. Timeouts and server failures stay errors.
fn found<T>(
    result: Result<T, hickory_resolver::ResolveError>,
) -> Result<Option<T>, hickory_resolver::ResolveError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.is_no_records_found() => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::{
        op::{Query, ResponseCode},
        ProtoError,
    };

    use super::found;

    fn negative_answer(code: ResponseCode) -> hickory_resolver::ResolveError {
        ProtoError::nx_error(Box::new(Query::new()), None, None, None, code, true, None).into()
    }

    #[test]
    fn missing_names_and_record_types_are_not_dns_failures() {
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            assert!(matches!(found::<()>(Err(negative_answer(code))), Ok(None)));
        }
        assert!(matches!(found(Ok(1)), Ok(Some(1))));
    }

    #[test]
    fn other_dns_errors_stay_failures() {
        let error: hickory_resolver::ResolveError = ProtoError::from("timed out").into();
        assert!(found::<()>(Err(error)).is_err());
    }
}
