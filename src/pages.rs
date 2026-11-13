//! HTML pages. The markup lives in `templates/`; askama compiles it into the binary
//! and HTML-escapes every `{{ value }}`.

use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::docs::DocsConfig;

#[derive(Template)]
#[template(path = "help.html")]
pub struct Help {
    pub dns_records: Vec<String>,
}

impl Help {
    pub fn new(config: &DocsConfig) -> Self {
        Self {
            dns_records: config.dns_records(),
        }
    }
}

#[derive(Template)]
#[template(path = "stats.html")]
pub struct StatsPage;

#[derive(Template)]
#[template(path = "domains.html")]
pub struct DomainsPage;

#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFound {
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

    use super::{Help, NotFound};

    #[test]
    fn values_are_html_escaped() {
        let page = NotFound {
            help_url: Some("https://x/\"><script>".to_owned()),
        }
        .render()
        .unwrap();
        assert!(!page.contains("<script>"));
    }

    #[test]
    fn help_page_lists_records() {
        let page = Help {
            dns_records: vec!["example.com. 14400 A     192.0.2.1".to_owned()],
        }
        .render()
        .unwrap();
        assert!(page.contains("example.com. 14400 A     192.0.2.1"));
    }
}
