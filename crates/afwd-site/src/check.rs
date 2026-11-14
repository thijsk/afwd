//! `/api/check/{domain}`: what this service sees for a domain, so owners can debug their DNS.

use std::net::IpAddr;

use serde::Serialize;

use afwd_core::{config::parse_txt_record, dns::DnsConfig, redirect::redirect_url};

pub const SAMPLE_PATH: &str = "/blog/post?x=1";

#[derive(Debug, Serialize)]
pub struct Check {
    pub domain: String,
    /// Each A/AAAA address and whether it belongs to this service. `None` when the
    /// service has no addresses to compare against.
    pub addresses: Vec<(IpAddr, Option<bool>)>,
    /// The target of the domain's CNAME record, if it has one.
    pub cname: Option<String>,
    /// The raw `v=afwd1` TXT record, if there is one.
    pub record: Option<String>,
    /// The name the TXT record was found at, such as `_afwd.example.com`.
    pub record_name: Option<String>,
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

/// `public` are the configured A/AAAA addresses. A domain that resolves to the current
/// addresses of `target` (through a CNAME, an ALIAS or a flattened CNAME) also points here.
pub async fn check(
    dns: &DnsConfig,
    public: &[IpAddr],
    target: Option<&str>,
    domain: String,
) -> Result<Check, hickory_resolver::ResolveError> {
    let target_addresses = async {
        match target {
            // The target is ours, so a failed lookup only means less to compare against.
            Some(target) => dns.addresses(target).await.unwrap_or_default(),
            None => Vec::new(),
        }
    };
    let (addresses, record, cname, target_addresses) = tokio::join!(
        dns.addresses(&domain),
        dns.find_record(&domain),
        dns.cname(&domain),
        target_addresses
    );
    let ours = public
        .iter()
        .chain(&target_addresses)
        .copied()
        .collect::<Vec<_>>();
    let addresses = mark_addresses(addresses?, &ours);
    let record = record?;

    let mut result = Check {
        domain,
        addresses,
        cname: cname?,
        record: record.as_ref().map(|found| found.text.clone()),
        record_name: record.map(|found| found.name),
        error: None,
        redirect: None,
        certificate: None,
    };
    match result.record.as_deref().map(parse_txt_record) {
        None => {}
        Some(Err(error)) => result.error = Some(error.to_string()),
        Some(Ok(config)) => {
            result.certificate = Some(config.request_certificate);
            result.redirect =
                redirect_url(&config, &result.domain, SAMPLE_PATH).map(|location| Redirect {
                    from: format!("http://{}{SAMPLE_PATH}", result.domain),
                    location,
                    status: config.status,
                });
        }
    }
    Ok(result)
}

/// Pairs each address with whether it is one of `ours`, or `None` when there is nothing
/// to compare against.
fn mark_addresses(addresses: Vec<IpAddr>, ours: &[IpAddr]) -> Vec<(IpAddr, Option<bool>)> {
    addresses
        .into_iter()
        .map(|address| (address, (!ours.is_empty()).then(|| ours.contains(&address))))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{mark_addresses, normalize_domain};

    #[test]
    fn addresses_are_compared_with_ours() {
        let ip = |value: &str| value.parse::<IpAddr>().unwrap();
        let ours = [ip("192.0.2.1"), ip("2001:db8::1")];
        assert_eq!(
            mark_addresses(
                vec![ip("192.0.2.1"), ip("198.51.100.1"), ip("2001:db8::1")],
                &ours
            ),
            [
                (ip("192.0.2.1"), Some(true)),
                (ip("198.51.100.1"), Some(false)),
                (ip("2001:db8::1"), Some(true)),
            ]
        );
        assert_eq!(
            mark_addresses(vec![ip("192.0.2.1")], &[]),
            [(ip("192.0.2.1"), None)]
        );
    }

    #[test]
    fn normalizes_and_validates_domains() {
        assert_eq!(
            normalize_domain(" Example.COM. ").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("_afwd-stats.example.com").as_deref(),
            Some("_afwd-stats.example.com")
        );
        for invalid in [
            "",
            "localhost",
            "127.0.0.1",
            "a..b",
            "exa mple.com",
            "<x>.com",
            "::1",
        ] {
            assert_eq!(normalize_domain(invalid), None, "{invalid}");
        }
    }
}
