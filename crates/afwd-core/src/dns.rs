use std::{net::IpAddr, time::Duration};

use hickory_resolver::proto::{
    op::ResponseCode,
    rr::{RData, RecordType},
    ProtoErrorKind,
};
use hickory_resolver::{
    config::ResolverConfig, name_server::TokioConnectionProvider, TokioResolver,
};
use thiserror::Error;

use crate::config::{parse_txt_record, ConfigError, ForwardingConfig};

/// The label in front of a name that holds its AFWD record. A name with a CNAME cannot
/// have a TXT record of its own, so `go.example.com CNAME fwd.afwd.nl` is configured at
/// `_afwd.go.example.com`. This is an extension of the afwd1 specification.
pub const RECORD_PREFIX: &str = "_afwd.";

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("DNS lookup failed")]
    Dns(#[from] hickory_resolver::ResolveError),
    #[error("AFWD configuration is invalid")]
    Config(#[from] ConfigError),
    #[error("no AFWD TXT record found")]
    NotFound,
    /// The record was found only because the `_afwd.` lookup failed; good enough to
    /// redirect, but not to request a certificate.
    #[error("the _afwd lookup failed")]
    Incomplete,
}

/// A `v=afwd1` TXT record and the name it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundRecord {
    pub name: String,
    pub text: String,
    /// Why the record is invalid before it is parsed: there is more than one, or it is
    /// not UTF-8.
    pub problem: Option<ConfigError>,
    /// Found on the name itself after the `_afwd.` lookup failed with SERVFAIL or
    /// REFUSED (step 3 of the lookup procedure).
    pub fallback: bool,
}

impl FoundRecord {
    pub fn config(&self) -> Result<ForwardingConfig, ConfigError> {
        match &self.problem {
            Some(problem) => Err(problem.clone()),
            None => parse_txt_record(&self.text),
        }
    }
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
        let found = self
            .find_record(host)
            .await?
            .ok_or(ResolveError::NotFound)?;
        Ok(found.config()?)
    }

    /// Like [`resolve`](Self::resolve), but a record found only after the `_afwd.`
    /// lookup failed is not enough: a certificate is a lasting decision.
    pub async fn resolve_for_certificate(
        &self,
        host: &str,
    ) -> Result<ForwardingConfig, ResolveError> {
        let found = self
            .find_record(host)
            .await?
            .ok_or(ResolveError::NotFound)?;
        if found.fallback {
            return Err(ResolveError::Incomplete);
        }
        Ok(found.config()?)
    }

    /// The `v=afwd1` TXT record that configures `host`. See [`find_record`].
    pub async fn find_record(
        &self,
        host: &str,
    ) -> Result<Option<FoundRecord>, hickory_resolver::ResolveError> {
        find_record(self, host).await
    }

    /// The target of the CNAME record at `host`, if it has one.
    pub async fn cname(
        &self,
        host: &str,
    ) -> Result<Option<String>, hickory_resolver::ResolveError> {
        Ok(Records::cnames(self, host).await?.into_iter().next())
    }

    /// The A and AAAA addresses of `host`, following CNAMEs.
    pub async fn addresses(
        &self,
        host: &str,
    ) -> Result<Vec<IpAddr>, hickory_resolver::ResolveError> {
        Ok(found(self.resolver.lookup_ip(fqdn(host)).await)?
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
}

/// The DNS lookups [`find_record`] needs, so the search order can be tested without DNS.
trait Records {
    /// The `v=afwd1` TXT record at `name`, following CNAMEs.
    async fn txt(&self, name: &str) -> Result<Option<FoundRecord>, hickory_resolver::ResolveError>;
    /// The targets of the CNAME records at `name`.
    async fn cnames(&self, name: &str) -> Result<Vec<String>, hickory_resolver::ResolveError>;
}

impl Records for DnsConfig {
    async fn txt(&self, name: &str) -> Result<Option<FoundRecord>, hickory_resolver::ResolveError> {
        let Some(records) = found(self.resolver.txt_lookup(fqdn(name)).await)? else {
            return Ok(None);
        };
        // The answer also holds any CNAMEs that were followed; the owner of the TXT
        // records is where the configuration lives.
        let mut owner = None;
        let texts = records
            .as_lookup()
            .record_iter()
            .filter_map(|record| {
                let RData::TXT(txt) = record.data() else {
                    return None;
                };
                owner.get_or_insert_with(|| display_name(&record.name().to_string()));
                Some(
                    txt.txt_data()
                        .iter()
                        .flat_map(|chunk| chunk.iter().copied())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        Ok(owner.and_then(|owner| afwd_record(owner, texts)))
    }

    async fn cnames(&self, name: &str) -> Result<Vec<String>, hickory_resolver::ResolveError> {
        let Some(lookup) = found(self.resolver.lookup(fqdn(name), RecordType::CNAME).await)? else {
            return Ok(Vec::new());
        };
        Ok(lookup
            .iter()
            .filter_map(|record| match record {
                RData::CNAME(target) => Some(display_name(&target.0.to_string())),
                _ => None,
            })
            .collect())
    }
}

/// Finds the `v=afwd1` TXT record for `host`. The first of these wins:
///
/// 1. `_afwd.<host>`
/// 2. `<host>` itself. When `host` is a CNAME, the resolver follows it, so
///    `www CNAME example.com` uses the record of `example.com`.
/// 3. `_afwd.<target>` for the target of a CNAME at `host`. This is how
///    `*.example.com CNAME example.com` finds a record kept at `_afwd.example.com`.
///
/// This is Section 4.2 of the specification (`spec/afwd-spec.txt`).
async fn find_record<R: Records>(
    records: &R,
    host: &str,
) -> Result<Option<FoundRecord>, hickory_resolver::ResolveError> {
    let host = host.trim_end_matches('.');
    let underscore = format!("{RECORD_PREFIX}{host}");
    let (own, direct) = tokio::join!(records.txt(&underscore), records.txt(host));
    match (own, direct) {
        (Ok(Some(found)), _) => return Ok(Some(found)),
        // A record on the name keeps working when a DNS server answers the `_afwd.`
        // query with SERVFAIL or REFUSED, as some mishandle underscore names. A timeout
        // may be temporary, so it does not count.
        (Err(error), Ok(Some(mut found))) if is_server_failure(&error) => {
            tracing::debug!(%error, host, "_afwd lookup failed; using the record on the name");
            found.fallback = true;
            return Ok(Some(found));
        }
        (Ok(None), Ok(Some(found))) => return Ok(Some(found)),
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(None), Ok(None)) => {}
    }

    // The TXT query for `host` already followed its CNAME, so only `_afwd.<target>` is
    // left to check.
    for target in records.cnames(host).await? {
        if let Some(found) = records.txt(&format!("{RECORD_PREFIX}{target}")).await? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// A fully qualified name, so the resolver never appends a search domain.
fn fqdn(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

/// A DNS name as shown to people: lowercase, without the trailing dot.
fn display_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The AFWD record among the TXT records at `owner`: the one whose first token is
/// exactly `v=afwd1`. More than one, or one that is not UTF-8, makes it invalid.
fn afwd_record(owner: String, texts: Vec<Vec<u8>>) -> Option<FoundRecord> {
    let mut matches = texts.into_iter().filter(|text| is_afwd_record(text));
    let first = matches.next()?;
    let problem = if matches.next().is_some() {
        Some(ConfigError::MultipleRecords)
    } else if std::str::from_utf8(&first).is_err() {
        Some(ConfigError::InvalidEncoding)
    } else {
        None
    };
    Some(FoundRecord {
        name: owner,
        text: String::from_utf8_lossy(&first).into_owned(),
        problem,
        fallback: false,
    })
}

/// `v=afwd1` followed by a space, a tab, or nothing: `v=afwd10` is another version.
fn is_afwd_record(text: &[u8]) -> bool {
    text.strip_prefix(b"v=afwd1")
        .is_some_and(|rest| matches!(rest.first(), None | Some(b' ' | b'\t')))
}

/// The response code of a DNS answer that held no records.
fn response_code(error: &hickory_resolver::ResolveError) -> Option<ResponseCode> {
    match error.proto()?.kind() {
        ProtoErrorKind::NoRecordsFound { response_code, .. } => Some(*response_code),
        _ => None,
    }
}

/// A DNS server answered, but with SERVFAIL or REFUSED.
fn is_server_failure(error: &hickory_resolver::ResolveError) -> bool {
    matches!(
        response_code(error),
        Some(ResponseCode::ServFail | ResponseCode::Refused)
    )
}

/// NXDOMAIN and NODATA answers mean there is no record here; they are not failures.
/// The resolver reports SERVFAIL and REFUSED the same way, so the response code
/// decides. Timeouts and server failures stay errors.
fn found<T>(
    result: Result<T, hickory_resolver::ResolveError>,
) -> Result<Option<T>, hickory_resolver::ResolveError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if matches!(
                response_code(&error),
                Some(ResponseCode::NXDomain | ResponseCode::NoError)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
#[cfg(test)]
mod tests {
    use hickory_resolver::proto::{
        op::{Query, ResponseCode},
        ProtoError,
    };

    use std::collections::{HashMap, HashSet};

    use super::{afwd_record, find_record, found, FoundRecord, Records};
    use crate::config::ConfigError;

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
    fn servfail_and_refused_are_dns_failures() {
        for code in [ResponseCode::ServFail, ResponseCode::Refused] {
            assert!(found::<()>(Err(negative_answer(code))).is_err(), "{code:?}");
        }
    }

    fn texts(texts: &[&[u8]]) -> Vec<Vec<u8>> {
        texts.iter().map(|text| text.to_vec()).collect()
    }

    #[test]
    fn the_version_tag_must_be_a_whole_token() {
        let owner = || "example.com".to_owned();
        assert!(afwd_record(owner(), texts(&[b"v=afwd10 dest=https://x/"])).is_none());
        assert!(afwd_record(owner(), texts(&[b"v=afwd1.1 dest=https://x/"])).is_none());
        assert!(afwd_record(owner(), texts(&[b"v=spf1 -all"])).is_none());
        for text in [
            &b"v=afwd1 dest=https://x/"[..],
            b"v=afwd1\tdest=https://x/",
            b"v=afwd1",
        ] {
            assert!(afwd_record(owner(), texts(&[text])).is_some());
        }
    }

    #[test]
    fn more_than_one_record_or_invalid_utf8_makes_the_record_invalid() {
        let owner = || "example.com".to_owned();
        let found = afwd_record(
            owner(),
            texts(&[
                b"v=afwd1 dest=https://a.example/",
                b"v=spf1 -all",
                b"v=afwd1 dest=https://b.example/",
            ]),
        )
        .unwrap();
        assert_eq!(found.config(), Err(ConfigError::MultipleRecords));

        let found = afwd_record(owner(), texts(&[b"v=afwd1 dest=https://a.example/\xff"])).unwrap();
        assert_eq!(found.config(), Err(ConfigError::InvalidEncoding));

        let found = afwd_record(owner(), texts(&[b"v=afwd1 dest=https://a.example/"])).unwrap();
        assert!(found.config().is_ok());
    }

    #[test]
    fn other_dns_errors_stay_failures() {
        let error: hickory_resolver::ResolveError = ProtoError::from("timed out").into();
        assert!(found::<()>(Err(error)).is_err());
    }

    /// A zone in memory. TXT lookups follow CNAMEs, like a recursive resolver does.
    #[derive(Default)]
    struct Zone {
        txt: HashMap<&'static str, &'static str>,
        cname: HashMap<&'static str, &'static str>,
        /// Names whose TXT query gets SERVFAIL.
        servfail: HashSet<&'static str>,
        /// Names whose TXT query times out.
        timeout: HashSet<&'static str>,
    }

    impl Records for Zone {
        async fn txt(
            &self,
            name: &str,
        ) -> Result<Option<FoundRecord>, hickory_resolver::ResolveError> {
            let mut name = name.to_owned();
            for _ in 0..8 {
                if self.servfail.contains(name.as_str()) {
                    return Err(negative_answer(ResponseCode::ServFail));
                }
                if self.timeout.contains(name.as_str()) {
                    return Err(ProtoError::from("timed out").into());
                }
                if let Some(text) = self.txt.get(name.as_str()) {
                    return Ok(afwd_record(name.clone(), vec![text.as_bytes().to_vec()]));
                }
                match self.cname.get(name.as_str()) {
                    Some(target) => name = (*target).to_owned(),
                    None => return Ok(None),
                }
            }
            Ok(None)
        }

        async fn cnames(&self, name: &str) -> Result<Vec<String>, hickory_resolver::ResolveError> {
            Ok(self
                .cname
                .get(name)
                .map(|target| vec![(*target).to_owned()])
                .unwrap_or_default())
        }
    }

    async fn lookup(zone: &Zone, host: &str) -> Option<(String, String)> {
        find_record(zone, host)
            .await
            .unwrap()
            .map(|found| (found.name, found.text))
    }

    fn at(name: &str, text: &str) -> Option<(String, String)> {
        Some((name.to_owned(), text.to_owned()))
    }

    const A: &str = "v=afwd1 dest=https://a.example/";
    const B: &str = "v=afwd1 dest=https://b.example/";

    #[tokio::test]
    async fn record_on_the_name_works_as_in_the_specification() {
        let zone = Zone {
            txt: HashMap::from([("example.com", A)]),
            ..Zone::default()
        };
        assert_eq!(lookup(&zone, "example.com").await, at("example.com", A));
        assert_eq!(lookup(&zone, "example.com.").await, at("example.com", A));
        assert_eq!(lookup(&zone, "other.example").await, None);
    }

    #[tokio::test]
    async fn underscore_record_wins_over_the_record_on_the_name() {
        let zone = Zone {
            txt: HashMap::from([("example.com", A), ("_afwd.example.com", B)]),
            ..Zone::default()
        };
        assert_eq!(
            lookup(&zone, "example.com").await,
            at("_afwd.example.com", B)
        );
    }

    #[tokio::test]
    async fn cname_to_the_service_is_configured_with_an_underscore_record() {
        let zone = Zone {
            txt: HashMap::from([("_afwd.go.example.com", A)]),
            cname: HashMap::from([("go.example.com", "fwd.afwd.nl")]),
            ..Zone::default()
        };
        assert_eq!(
            lookup(&zone, "go.example.com").await,
            at("_afwd.go.example.com", A)
        );
        // Without its own record, a CNAME to the service has no configuration.
        assert_eq!(lookup(&zone, "other.example.com").await, None);
        let zone = Zone {
            cname: HashMap::from([("go.example.com", "fwd.afwd.nl")]),
            ..Zone::default()
        };
        assert_eq!(lookup(&zone, "go.example.com").await, None);
    }

    #[tokio::test]
    async fn cname_to_the_apex_uses_the_apex_configuration() {
        // As in the specification: the record is on the apex itself.
        let zone = Zone {
            txt: HashMap::from([("example.com", A)]),
            cname: HashMap::from([("www.example.com", "example.com")]),
            ..Zone::default()
        };
        assert_eq!(lookup(&zone, "www.example.com").await, at("example.com", A));

        // The apex is flattened to the service and keeps its record at _afwd.
        let zone = Zone {
            txt: HashMap::from([("_afwd.example.com", A)]),
            cname: HashMap::from([("www.example.com", "example.com")]),
            ..Zone::default()
        };
        assert_eq!(
            lookup(&zone, "www.example.com").await,
            at("_afwd.example.com", A)
        );

        // A subdomain with its own record overrides the apex.
        let zone = Zone {
            txt: HashMap::from([("_afwd.example.com", A), ("_afwd.www.example.com", B)]),
            cname: HashMap::from([("www.example.com", "example.com")]),
            ..Zone::default()
        };
        assert_eq!(
            lookup(&zone, "www.example.com").await,
            at("_afwd.www.example.com", B)
        );
    }

    #[tokio::test]
    async fn non_afwd_txt_records_are_ignored() {
        let zone = Zone {
            txt: HashMap::from([("_afwd.example.com", "v=spf1 -all"), ("example.com", A)]),
            ..Zone::default()
        };
        assert_eq!(lookup(&zone, "example.com").await, at("example.com", A));
    }

    #[tokio::test]
    async fn servfail_on_the_underscore_name_falls_back_to_the_record_on_the_name() {
        let zone = Zone {
            txt: HashMap::from([("example.com", A)]),
            servfail: HashSet::from(["_afwd.example.com"]),
            ..Zone::default()
        };
        let found = find_record(&zone, "example.com").await.unwrap().unwrap();
        assert_eq!(
            (found.name.as_str(), found.text.as_str()),
            ("example.com", A)
        );
        // Good enough to redirect, but marked so no certificate is requested.
        assert!(found.fallback);

        let zone = Zone {
            servfail: HashSet::from(["_afwd.example.com"]),
            ..Zone::default()
        };
        assert!(find_record(&zone, "example.com").await.is_err());
    }

    #[tokio::test]
    async fn a_timeout_on_the_underscore_name_fails_the_lookup() {
        let zone = Zone {
            txt: HashMap::from([("example.com", A)]),
            timeout: HashSet::from(["_afwd.example.com"]),
            ..Zone::default()
        };
        assert!(find_record(&zone, "example.com").await.is_err());
    }

    #[tokio::test]
    async fn an_invalid_underscore_record_is_not_replaced_by_the_record_on_the_name() {
        let zone = Zone {
            txt: HashMap::from([
                ("example.com", A),
                ("_afwd.example.com", "v=afwd1 preserve=y"),
            ]),
            ..Zone::default()
        };
        let found = find_record(&zone, "example.com").await.unwrap().unwrap();
        assert_eq!(found.name, "_afwd.example.com");
        assert!(found.config().is_err());
    }

    #[tokio::test]
    async fn failing_record_on_the_name_does_not_hide_the_underscore_record() {
        let zone = Zone {
            txt: HashMap::from([("_afwd.example.com", A)]),
            timeout: HashSet::from(["example.com"]),
            ..Zone::default()
        };
        assert_eq!(
            lookup(&zone, "example.com").await,
            at("_afwd.example.com", A)
        );
    }
}
