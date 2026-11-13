use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
pub struct DocsConfig {
    public_ipv4: Vec<Ipv4Addr>,
    public_ipv6: Vec<Ipv6Addr>,
    help_domain: Option<String>,
}

impl DocsConfig {
    pub fn with_help_domain(domain: impl Into<String>) -> Self {
        Self {
            help_domain: normalize_help_domain(domain.into()),
            ..Self::default()
        }
    }

    pub fn from_env() -> Self {
        Self {
            public_ipv4: parse_addresses::<Ipv4Addr>("AFWD_PUBLIC_IPV4"),
            public_ipv6: parse_addresses::<Ipv6Addr>("AFWD_PUBLIC_IPV6"),
            help_domain: normalize_help_domain(
                std::env::var("AFWD_HELP_DOMAIN").unwrap_or_else(|_| "afwd.nl".to_owned()),
            ),
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
}

fn normalize_help_domain(domain: String) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
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

    /// Example A/AAAA/TXT records for the help page, using the configured public addresses.
    pub fn dns_records(&self) -> Vec<String> {
        let mut records = self
            .public_ipv4
            .iter()
            .map(|address| format!("example.com. 14400 A     {address}"))
            .chain(
                self.public_ipv6
                    .iter()
                    .map(|address| format!("example.com. 14400 AAAA  {address}")),
            )
            .collect::<Vec<_>>();

        if records.is_empty() {
            records.push("Set AFWD_PUBLIC_IPV4 or AFWD_PUBLIC_IPV6".to_owned());
        }
        records
            .push("example.com. 14400 TXT   \"v=afwd1 dest=https://www.example.net/\"".to_owned());
        records
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
        };

        let page = config.dns_records().join(
            "
",
        );

        assert!(page.contains("example.com. 14400 A     192.0.2.1"));
        assert!(page.contains("example.com. 14400 A     192.0.2.2"));
        assert!(page.contains("example.com. 14400 AAAA  2001:db8::1"));
        assert!(page.contains("example.com. 14400 AAAA  2001:db8::2"));
        assert_eq!(
            DocsConfig::with_help_domain("afwd.nl")
                .help_url()
                .as_deref(),
            Some("https://afwd.nl/")
        );
    }
}
