use std::sync::Arc;

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, HOST, LOCATION, REFERER},
        uri::Authority,
        HeaderMap, HeaderValue, StatusCode, Uri,
    },
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::{
    dns::{DnsConfig, ResolveError},
    docs::{render, DocsConfig},
    redirect::redirect_url,
    stats::Stats,
};

#[derive(serde::Deserialize)]
struct CertificateQuery {
    domain: String,
}

#[derive(Clone)]
pub struct AppState {
    pub dns: DnsConfig,
    pub docs: DocsConfig,
    pub stats: Option<Stats>,
}

pub fn router(dns: DnsConfig) -> Router {
    router_with_docs(dns, DocsConfig::default())
}

pub fn router_with_docs(dns: DnsConfig, docs: DocsConfig) -> Router {
    router_with_stats(dns, docs, None)
}

pub fn router_with_stats(dns: DnsConfig, docs: DocsConfig, stats: Option<Stats>) -> Router {
    let state = Arc::new(AppState { dns, docs, stats });
    Router::new()
        .route("/healthz", get(health))
        .route("/internal/cert-check", get(cert_check))
        .fallback(forward)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn cert_check(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CertificateQuery>,
) -> StatusCode {
    let domain = query.domain.trim_end_matches('.');
    if is_ip_address(domain) {
        return StatusCode::FORBIDDEN;
    }
    if state.docs.is_help_domain(domain) {
        return StatusCode::OK;
    }

    match state.dns.resolve(domain).await {
        Ok(config) if config.request_certificate => StatusCode::OK,
        Ok(_) | Err(ResolveError::NotFound | ResolveError::Config(_)) => StatusCode::FORBIDDEN,
        Err(ResolveError::Dns(_)) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn forward(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(host) = request_host(&headers) else {
        return (StatusCode::BAD_REQUEST, "host header required").into_response();
    };
    let is_root = uri.path() == "/" && uri.query().is_none();
    if is_root && (is_ip_address(&host) || state.docs.is_help_domain(&host)) {
        if state.docs.is_help_domain(&host) {
            record(&state, &host, "200", &uri, &headers);
        }
        return axum::response::Html(render(&state.docs)).into_response();
    }
    if state.docs.is_help_domain(&host) {
        if uri.path() == "/.well-known/security.txt" {
            let expires = (OffsetDateTime::now_utc() + Duration::days(365))
                .format(&Rfc3339)
                .unwrap();
            return (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                format!("Contact: mailto:info@trilobit.nl\nExpires: {expires}\n"),
            )
                .into_response();
        }
        if uri.path() == "/stats" {
            record(&state, &host, "200", &uri, &headers);
            return Html(STATS_PAGE).into_response();
        }
        if let Some(domain) = uri.path().strip_prefix("/api/stats/") {
            return stats_api(&state, &headers, domain).await;
        }
    }

    match state.dns.resolve(&host).await {
        Ok(config) => {
            let Some(location) = redirect_url(
                &config,
                &host,
                uri.path_and_query().map_or("/", |value| value.as_str()),
            ) else {
                record(&state, &host, "400", &uri, &headers);
                return (StatusCode::BAD_REQUEST, "invalid request URI").into_response();
            };
            let mut response = StatusCode::from_u16(config.status)
                .unwrap_or(StatusCode::FOUND)
                .into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            record(&state, &host, response.status().as_str(), &uri, &headers);
            response
        }
        Err(error @ (ResolveError::NotFound | ResolveError::Config(_))) => {
            // Unknown hosts are not recorded, so forged Host headers cannot fill the database.
            if matches!(error, ResolveError::Config(_)) {
                record(&state, &host, "config-error", &uri, &headers);
            }
            let body = state.docs.help_url().map_or_else(
                || "Forwarding configuration not found.".to_owned(),
                |help_url| {
                    format!(
                        "Forwarding configuration not found. Read the <a href=\"{help_url}\">AFWD help page</a>."
                    )
                },
            );
            (StatusCode::NOT_FOUND, Html(body)).into_response()
        }
        Err(ResolveError::Dns(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, "DNS lookup failed").into_response()
        }
    }
}

fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn record(state: &AppState, host: &str, status: &str, uri: &Uri, headers: &HeaderMap) {
    if let Some(stats) = &state.stats {
        let referer = headers.get(REFERER).and_then(|value| value.to_str().ok());
        stats.record(host, status, uri.path(), referer);
    }
}

async fn stats_api(state: &AppState, headers: &HeaderMap, domain: &str) -> Response {
    let Some(stats) = &state.stats else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let hash = Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Plain comparison is fine: the expected hash is public in DNS.
    if !state.dns.stats_hashes(&domain).await.contains(&hash) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match stats.query(domain).await {
        Ok(report) => ([(CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "stats query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

// Paths and referrers are attacker-controlled, so the page only renders them via textContent.
const STATS_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AFWD statistics</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { line-height: 1.5; margin: 0 auto; max-width: 58rem; padding: 2rem 1.25rem; }
    pre { overflow-x: auto; padding: 1rem; background: #222; border-radius: .4rem; }
    input { width: 100%; box-sizing: border-box; }
    .warning { border: 3px solid #d33; border-radius: .4rem; padding: 1rem; font-size: 1.15rem; }
    table { border-collapse: collapse; width: 100%; }
    td { border-bottom: 1px solid #8888; padding: .25rem .5rem; overflow-wrap: anywhere; }
    td:nth-child(2) { text-align: right; white-space: nowrap; }
    td:nth-child(3) { width: 40%; }
    .bar { height: .8rem; min-width: 1px; background: #4a8; border-radius: .2rem; }
  </style>
</head>
<body>
  <h1>AFWD statistics</h1>
  <p class="warning"><strong>You are responsible for storing your token.</strong> AFWD does not store the token and cannot recover it. If you lose it, create a new token and replace the DNS record.</p>
  <form id="view">
    <p><label>Domain <input id="domain" autocomplete="username" placeholder="example.com" required></label></p>
    <h2>1. Create a token</h2>
    <p>The token is created in your browser and is never sent to the server. Keep it secret.</p>
    <button type="button" id="generate">Create token</button>
    <pre id="setup"></pre>
    <h2>2. View statistics</h2>
    <p><label>Token <input id="token" type="password" autocomplete="current-password" required></label></p>
    <p><button type="button" id="copy">Copy token</button> <span id="copied"></span></p>
    <p>Your browser can save the domain and token in its password manager.</p>
    <button>Show</button>
  </form>
  <div id="result"></div>
  <script>
    const hex = async (text) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))]
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('generate').onclick = async () => {
      const domain = document.getElementById('domain').value.trim().replace(/\.$/, '') || 'example.com';
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const token = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      document.getElementById('setup').textContent =
        `Token: ${token}\n\nAdd this DNS record:\n_afwd-stats.${domain}. 3600 TXT "v=afwdstats1 h=${await hex(token)}"`;
      document.getElementById('token').value = token;
    };
    document.getElementById('copy').onclick = async () => {
      const status = document.getElementById('copied');
      try {
        await navigator.clipboard.writeText(document.getElementById('token').value);
        status.textContent = 'Copied.';
      } catch {
        status.textContent = 'Copy failed. Select the token above and copy it manually.';
      }
    };
    const sum = (pairs) => [...pairs.reduce((map, [key, n]) => map.set(key, (map.get(key) || 0) + n), new Map())];
    const section = (title, rows) => {
      const heading = document.createElement('h3');
      heading.textContent = title;
      const table = document.createElement('table');
      const max = Math.max(1, ...rows.map(([, n]) => n));
      for (const [label, n] of rows) {
        const row = table.insertRow();
        row.insertCell().textContent = label;
        row.insertCell().textContent = n;
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.width = `${(100 * n) / max}%`;
        row.insertCell().append(bar);
      }
      document.getElementById('result').append(heading, rows.length ? table : 'No data yet.');
    };
    document.getElementById('view').onsubmit = async (event) => {
      event.preventDefault();
      const domain = document.getElementById('domain').value.trim();
      const response = await fetch(`/api/stats/${encodeURIComponent(domain)}`, {
        headers: { Authorization: `Bearer ${document.getElementById('token').value.trim()}` },
      });
      const result = document.getElementById('result');
      if (!response.ok) {
        result.textContent = `Error ${response.status}`;
        return;
      }
      const data = await response.json();
      result.replaceChildren();
      section('Hits per day (UTC)', sum(data.hits.map(([hour, , n]) => [new Date(hour * 1000).toISOString().slice(0, 10), n])));
      section('Status', sum(data.hits.map(([, status, n]) => [status, n])).sort((a, b) => b[1] - a[1]));
      section('Top paths', data.paths);
      section('Top referrers', data.referrers);
    };
  </script>
</body>
</html>
"#;

fn request_host(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(HOST)?.to_str().ok()?;
    let authority = value.parse::<Authority>().ok()?;
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    Some(host.trim_end_matches('.').to_owned())
}

#[cfg(test)]
mod tests {
    use super::request_host;
    use axum::http::{header::HOST, HeaderMap, HeaderValue};

    #[test]
    fn ip_addresses_are_not_treated_as_domain_names() {
        assert!(super::is_ip_address("127.0.0.1"));
        assert!(super::is_ip_address("::1"));
        assert!(!super::is_ip_address("example.com"));
    }

    #[test]
    fn strips_port_from_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("127.0.0.1:8080"));
        assert_eq!(request_host(&headers), Some("127.0.0.1".to_owned()));

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("[::1]:8443"));
        assert_eq!(request_host(&headers), Some("::1".to_owned()));
    }
}
