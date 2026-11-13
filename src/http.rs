use std::sync::Arc;

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, HOST, LOCATION, REFERER},
        uri::Authority,
        HeaderMap, HeaderValue, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::{
    dns::{DnsConfig, ResolveError},
    docs::DocsConfig,
    pages::{self, respond},
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
        return respond(StatusCode::OK, pages::Help::new(&state.docs));
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
        if uri.path() == "/robots.txt" {
            return (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                "User-agent: *\nDisallow: /api/\n",
            )
                .into_response();
        }
        if uri.path() == "/stats" {
            record(&state, &host, "200", &uri, &headers);
            return respond(StatusCode::OK, pages::StatsPage);
        }
        if uri.path() == "/domains" {
            return respond(StatusCode::OK, pages::DomainsPage);
        }
        if uri.path() == "/api/domains" {
            let Some(stats) = &state.stats else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let excluded_host = state.docs.help_domain().unwrap_or_default();
            return match stats.top_domains(excluded_host).await {
                Ok(domains) => ([(CACHE_CONTROL, "no-store")], Json(domains)).into_response(),
                Err(error) => {
                    tracing::warn!(%error, "domain leaderboard query failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            };
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
            respond(
                StatusCode::NOT_FOUND,
                pages::NotFound {
                    help_url: state.docs.help_url(),
                },
            )
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
