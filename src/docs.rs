use std::net::{Ipv4Addr, Ipv6Addr};

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

    pub fn help_url(&self) -> Option<String> {
        self.help_domain
            .as_deref()
            .map(|domain| format!("https://{}/", html_escape(domain)))
    }
}

fn normalize_help_domain(domain: String) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

pub fn render(config: &DocsConfig) -> String {
    let mut records = config
        .public_ipv4
        .iter()
        .map(|address| format!("example.com. 14400 A     {address}"))
        .chain(
            config
                .public_ipv6
                .iter()
                .map(|address| format!("example.com. 14400 AAAA  {address}")),
        )
        .collect::<Vec<_>>();

    if records.is_empty() {
        records.push("Set AFWD_PUBLIC_IPV4 or AFWD_PUBLIC_IPV6".to_owned());
    }
    records.push("example.com. 14400 TXT   \"v=afwd1 dest=https://www.example.net/\"".to_owned());

    DOCS_TEMPLATE.replace("{DNS_RECORDS}", &records.join("\n"))
}

const DOCS_TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AFWD - Free Web Forwarding</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { line-height: 1.5; margin: 0 auto; max-width: 58rem; padding: 2rem 1.25rem; }
    code, pre { font-family: ui-monospace, monospace; }
    pre { overflow-x: auto; padding: 1rem; background: #222; border-radius: .4rem; }
    h1 { margin-top: 0; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid #8888; padding: .5rem; text-align: left; }
  </style>
</head>
<body>
  <h1>AFWD</h1>
  <p>Free DNS-based web forwarding. No signup or login is required.</p>
  <p>This free service is provided by <a href="https://www.trilobit.nl/">Trilobit BV</a>.</p>

  <h2>DNS setup</h2>
  <p>Point your domain at this service with A and/or AAAA records. For a subdomain, use a CNAME pointing to the configured domain.</p>
  <p>Replace <code>example.com</code> with your domain. Add these A and AAAA records at your DNS provider:</p>
  <pre>{DNS_RECORDS}</pre>
  <p>To forward all subdomains, add this wildcard CNAME record:</p>
  <pre>*.example.com. 14400 CNAME example.com.</pre>
  <p>SSL/TLS certificates are provided automatically for HTTPS. Certificates renew automatically while your DNS records remain active.</p>

  <h2>TXT options</h2>
  <table>
    <tr><th>Option</th><th>Values</th><th>Default</th><th>Meaning</th></tr>
    <tr><td><code>dest</code></td><td>HTTP or HTTPS URL</td><td>required</td><td>Forwarding destination.</td></tr>
    <tr><td><code>preserve</code></td><td><code>y</code> or <code>n</code></td><td><code>n</code></td><td>Keep the source query string.</td></tr>
    <tr><td><code>append</code></td><td><code>y</code> or <code>n</code></td><td><code>n</code></td><td>Append the source domain as <code>domain=...</code>.</td></tr>
    <tr><td><code>type</code></td><td>301, 302, 307, 308, perm, temp</td><td>302</td><td>HTTP redirect status.</td></tr>
    <tr><td><code>cert</code></td><td><code>no</code></td><td>enabled</td><td>Prevent automatic HTTPS certificate issuance.</td></tr>
  </table>

  <h2>Examples</h2>
  <pre>v=afwd1 dest=https://example.net/
v=afwd1 preserve=y type=308 dest=https://example.net/
v=afwd1 type=perm append=y dest=https://example.net/?domain=</pre>

  <h2>Redirect status codes</h2>
  <p>The <code>type</code> option controls the HTTP response. The default is <code>302</code>.</p>
  <table>
    <tr><th>Code</th><th>Name</th><th>Use it when</th></tr>
    <tr><td><code>301</code> or <code>perm</code></td><td>Moved Permanently</td><td>The destination will not change. Browsers and search engines can cache this redirect.</td></tr>
    <tr><td><code>302</code> or <code>temp</code></td><td>Found</td><td>The destination can change. This is the default and is suitable for most forwarding rules.</td></tr>
    <tr><td><code>307</code></td><td>Temporary Redirect</td><td>The destination can change and the client must keep the original HTTP method and request body.</td></tr>
    <tr><td><code>308</code></td><td>Permanent Redirect</td><td>The destination will not change and the client must keep the original HTTP method and request body.</td></tr>
  </table>
  <p>Use <code>307</code> or <code>308</code> when forwarding requests such as POST. Some clients can change POST requests to GET with <code>301</code> or <code>302</code>.</p>

  <h2>HTTPS</h2>
  <p>SSL/TLS certificates are provided automatically when you use HTTPS. Visit your domain after DNS changes so certificate setup can start.</p>
  <h2>Statistics</h2>
  <p>The service counts the requests to your domain: hits per hour and status, paths, and referrer domains. It does not store IP addresses, user agents, or query strings. Statistics are kept for 90 days.</p>
  <p>To see the statistics for your domain:</p>
  <ol>
    <li>Open the <a href="/stats">statistics page</a> and click <em>Create token</em>. Your browser creates the token. Keep the token secret.</li>
    <li>Add the TXT record that the page shows. It contains the SHA-256 hash of the token, not the token:
      <pre>_afwd-stats.example.com. 3600 TXT "v=afwdstats1 h=&lt;sha256 hex of token&gt;"</pre></li>
    <li>Enter your domain and the token on the statistics page.</li>
  </ol>
  <p>To give access to more tokens, add more <code>h=</code> records. To remove access, delete the record.</p>
    <p>This service is based on the specifications defined by <a href="https://afwd.uk/">afwd.uk</a>.</p>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::{render, DocsConfig};
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

        let page = render(&config);

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
