//! HTML pages. The markup lives in `templates/`; askama compiles it into the binary
//! and HTML-escapes every `{{ value }}`.

use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::docs::DocsConfig;

#[derive(Template)]
#[template(path = "index.html")]
pub struct Landing {
    /// Comma-separated, for the record builder.
    pub ipv4: String,
    pub ipv6: String,
    /// The hostname for CNAME and ALIAS records; empty when there is none.
    pub target: String,
    pub canonical: Option<String>,
}

impl Landing {
    pub fn new(config: &DocsConfig) -> Self {
        let join = |addresses: Vec<String>| addresses.join(",");
        Self {
            ipv4: join(
                config
                    .public_ipv4()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
            ipv6: join(
                config
                    .public_ipv6()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
            target: config.target_host().unwrap_or_default().to_owned(),
            canonical: config.page_url("/"),
        }
    }

    /// The address shown in the "how it works" example.
    fn example_address(&self) -> &str {
        self.ipv4
            .split(',')
            .next()
            .filter(|address| !address.is_empty())
            .unwrap_or("192.0.2.1")
    }
}

#[derive(Template)]
#[template(path = "docs.html")]
pub struct Docs {
    /// Example A and AAAA records.
    pub address_records: Vec<String>,
    pub target_host: Option<String>,
    pub canonical: Option<String>,
}

impl Docs {
    pub fn new(config: &DocsConfig) -> Self {
        Self {
            address_records: config.address_records(),
            target_host: config.target_host().map(str::to_owned),
            canonical: config.page_url("/docs"),
        }
    }
}

#[derive(Template)]
#[template(path = "stats.html")]
pub struct StatsPage {
    pub canonical: Option<String>,
}

#[derive(Template)]
#[template(path = "domains.html")]
pub struct DomainsPage {
    pub canonical: Option<String>,
}

/// The specification, already laid out and escaped as HTML.
#[derive(Template)]
#[template(path = "spec.html")]
pub struct SpecPage {
    pub html: &'static str,
    pub canonical: Option<String>,
}

/// A help-site path that does not exist.
#[derive(Template)]
#[template(path = "page_not_found.html")]
pub struct PageNotFound {
    pub canonical: Option<String>,
}

/// A forwarded domain without a usable AFWD record.
#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFound {
    pub domain: String,
    /// Why the AFWD record that was found cannot be used; `None` when there is no record.
    pub reason: Option<String>,
    pub help_url: Option<String>,
}

pub fn respond(status: StatusCode, page: impl Template) -> Response {
    match page.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "page render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{Docs, Landing, NotFound};

    #[test]
    fn values_are_html_escaped() {
        let page = NotFound {
            domain: "<script>.example".to_owned(),
            reason: Some("unsupported token <script>".to_owned()),
            help_url: Some("https://x/\"><script>".to_owned()),
        }
        .render()
        .unwrap();
        assert!(!page.contains("<script>"));
    }

    #[test]
    fn docs_page_lists_records() {
        let page = Docs {
            address_records: vec!["example.com. 14400 A     192.0.2.1".to_owned()],
            target_host: Some("fwd.afwd.nl".to_owned()),
            canonical: None,
        }
        .render()
        .unwrap();
        assert!(page.contains("example.com. 14400 A     192.0.2.1"));
        assert!(page.contains("go.example.com.       14400 CNAME fwd.afwd.nl."));
        assert!(page.contains("example.com.       14400 ALIAS fwd.afwd.nl."));
        assert!(page.contains("_afwd.go.example.com. 14400 TXT"));

        // Without a target host only the A and AAAA records are offered.
        let page = Docs {
            address_records: vec!["example.com. 14400 A     192.0.2.1".to_owned()],
            target_host: None,
            canonical: None,
        }
        .render()
        .unwrap();
        assert!(page.contains("example.com. 14400 A     192.0.2.1"));
        assert!(!page.contains("ALIAS"));

        let page = Docs {
            address_records: Vec::new(),
            target_host: None,
            canonical: None,
        }
        .render()
        .unwrap();
        assert!(page.contains("Set <code>AFWD_PUBLIC_IPV4</code>"));
    }

    #[test]
    fn landing_page_uses_the_first_public_address() {
        let page = Landing {
            ipv4: "198.51.100.7,198.51.100.8".to_owned(),
            ipv6: String::new(),
            target: "fwd.afwd.nl".to_owned(),
            canonical: None,
        };
        assert_eq!(page.example_address(), "198.51.100.7");
        let html = page.render().unwrap();
        assert!(html.contains("data-ipv4=\"198.51.100.7,198.51.100.8\""));
        assert!(html.contains("data-target=\"fwd.afwd.nl\""));
        assert!(html.contains("<option value=\"alias\">"));
        assert!(html.contains("<option value=\"a\">"));
    }

    #[test]
    fn landing_page_without_target_offers_only_addresses() {
        let html = Landing {
            ipv4: "198.51.100.7".to_owned(),
            ipv6: String::new(),
            target: String::new(),
            canonical: None,
        }
        .render()
        .unwrap();
        assert!(!html.contains("id=\"b-point\""));
        assert!(html.contains("example.com.&nbsp; A&nbsp; 198.51.100.7"));

        // Without addresses, the A option is left out.
        let html = Landing {
            ipv4: String::new(),
            ipv6: String::new(),
            target: "fwd.afwd.nl".to_owned(),
            canonical: None,
        }
        .render()
        .unwrap();
        assert!(html.contains("id=\"b-point\""));
        assert!(!html.contains("<option value=\"a\">"));
    }
}
