//! `/api/check/{domain}`: what this service sees for a domain, so owners can debug their DNS.

use std::net::IpAddr;

use serde::Serialize;

use crate::{config::parse_txt_record, dns::DnsConfig, redirect::redirect_url};

pub const SAMPLE_PATH: &str = "/blog/post?x=1";

#[derive(Debug, Serialize)]
pub struct Check {
    pub domain: String,
    /// Each A/AAAA address and whether it belongs to this service. `None` when the
    /// service has no public addresses configured to compare against.
    pub addresses: Vec<(IpAddr, Option<bool>)>,
    /// The raw `v=afwd1` TXT record, if there is one.
    pub record: Option<String>,
    /// Why the record cannot be used.
    pub error: Option<String>,
    pub redirect: Option<Redirect>,
    pub certificate: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Redirect {
    pub from: String,
    pub location: String,
    pub status: u16,
}

/// Lowercases and validates a domain name typed by a user. Returns `None` for IP
/// addresses and anything that is not a plausible DNS name.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = domain.len() <= 253
        && domain.contains('.')
        && domain.parse::<IpAddr>().is_err()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    valid.then_some(domain)
}

pub async fn check(
    dns: &DnsConfig,
    public: &[IpAddr],
    domain: String,
) -> Result<Check, hickory_resolver::ResolveError> {
    let (addresses, record) = tokio::join!(dns.addresses(&domain), dns.find_record(&domain));
    let addresses = addresses?
        .into_iter()
        .map(|address| (address, (!public.is_empty()).then(|| public.contains(&address))))
        .collect();
    let record = record?;

    let mut result = Check {
        domain,
        addresses,
        record: record.clone(),
        error: None,
        redirect: None,
        certificate: None,
    };
    match record.as_deref().map(parse_txt_record) {
        None => {}
        Some(Err(error)) => result.error = Some(error.to_string()),
        Some(Ok(config)) => {
            result.certificate = Some(config.request_certificate);
            result.redirect = redirect_url(&config, &result.domain, SAMPLE_PATH).map(|location| {
                Redirect {
                    from: format!("http://{}{SAMPLE_PATH}", result.domain),
                    location,
                    status: config.status,
                }
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::normalize_domain;

    #[test]
    fn normalizes_and_validates_domains() {
        assert_eq!(normalize_domain(" Example.COM. ").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("_afwd-stats.example.com").as_deref(), Some("_afwd-stats.example.com"));
        for invalid in ["", "localhost", "127.0.0.1", "a..b", "exa mple.com", "<x>.com", "::1"] {
            assert_eq!(normalize_domain(invalid), None, "{invalid}");
        }
    }
}
