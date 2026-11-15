use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
pub struct DocsConfig {
    public_ipv4: Vec<Ipv4Addr>,
    public_ipv6: Vec<Ipv6Addr>,
    help_domain: Option<String>,
    target_host: Option<String>,
}

impl DocsConfig {
    pub fn with_help_domain(domain: impl Into<String>) -> Self {
        Self {
            help_domain: normalize_host(domain.into()),
            ..Self::default()
        }
    }

    /// The hostname that domains point at with a CNAME or ALIAS record.
    pub fn with_target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = normalize_host(host.into());
        self
    }

    pub fn from_env() -> Self {
        let help_domain = normalize_host(
            std::env::var("AFWD_HELP_DOMAIN").unwrap_or_else(|_| "afwd.nl".to_owned()),
        );
        // Set AFWD_TARGET_HOST to an empty value to offer only A and AAAA records.
        let target_host = match std::env::var("AFWD_TARGET_HOST") {
            Ok(host) => normalize_host(host),
            Err(_) => help_domain.as_deref().map(|domain| format!("fwd.{domain}")),
        };
        Self {
            public_ipv4: parse_addresses::<Ipv4Addr>("AFWD_PUBLIC_IPV4"),
            public_ipv6: parse_addresses::<Ipv6Addr>("AFWD_PUBLIC_IPV6"),
            help_domain,
            target_host,
        }
    }

    pub fn is_help_domain(&self, host: &str) -> bool {
        self.help_domain
            .as_deref()
            .is_some_and(|domain| domain.eq_ignore_ascii_case(host))
    }

    pub fn help_domain(&self) -> Option<&str> {
        self.help_domain.as_deref()
    }

    pub fn help_url(&self) -> Option<String> {
        self.help_domain
            .as_deref()
            .map(|domain| format!("https://{domain}/"))
    }

    /// The address of a help site page, for canonical links and the sitemap.
    pub fn page_url(&self, path: &str) -> Option<String> {
        self.help_domain
            .as_deref()
            .map(|domain| format!("https://{domain}{path}"))
    }

    pub fn target_host(&self) -> Option<&str> {
        self.target_host.as_deref()
    }

    pub fn is_target_host(&self, host: &str) -> bool {
        self.target_host
            .as_deref()
            .is_some_and(|target| target.eq_ignore_ascii_case(host))
    }
}

fn normalize_host(host: String) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn parse_addresses<T>(name: &str) -> Vec<T>
where
    T: std::str::FromStr,
{
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect()
}

impl DocsConfig {
    pub fn public_ipv4(&self) -> &[Ipv4Addr] {
        &self.public_ipv4
    }

    pub fn public_ipv6(&self) -> &[Ipv6Addr] {
        &self.public_ipv6
    }

    pub fn public_addresses(&self) -> Vec<IpAddr> {
        let v4 = self.public_ipv4.iter().copied().map(IpAddr::V4);
        let v6 = self.public_ipv6.iter().copied().map(IpAddr::V6);
        v4.chain(v6).collect()
    }

    /// Example A and AAAA records for the docs, using the configured public addresses.
    pub fn address_records(&self) -> Vec<String> {
        self.public_ipv4
            .iter()
            .map(|address| format!("example.com. 14400 A     {address}"))
            .chain(
                self.public_ipv6
                    .iter()
                    .map(|address| format!("example.com. 14400 AAAA  {address}")),
            )
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::DocsConfig;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn renders_multiple_public_addresses() {
        let config = DocsConfig {
            public_ipv4: vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)],
            public_ipv6: vec![
                "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
            ],
            help_domain: Some("afwd.nl".to_owned()),
            target_host: None,
        };

        assert_eq!(
            config.address_records(),
            [
                "example.com. 14400 A     192.0.2.1",
                "example.com. 14400 A     192.0.2.2",
                "example.com. 14400 AAAA  2001:db8::1",
                "example.com. 14400 AAAA  2001:db8::2",
            ]
        );
        assert!(DocsConfig::default().address_records().is_empty());
        assert_eq!(
            DocsConfig::with_help_domain("afwd.nl")
                .help_url()
                .as_deref(),
            Some("https://afwd.nl/")
        );
    }

    #[test]
    fn target_host_is_normalized() {
        let config = DocsConfig::with_help_domain("afwd.nl").with_target_host(" FWD.afwd.nl. ");
        assert_eq!(config.target_host(), Some("fwd.afwd.nl"));
        assert!(config.is_target_host("Fwd.Afwd.nl"));
        assert!(!config.is_target_host("afwd.nl"));
        assert_eq!(
            DocsConfig::default().with_target_host("  ").target_host(),
            None
        );
    }
}
