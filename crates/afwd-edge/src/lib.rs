//! The forwarding service: every host except the help domain. It answers Caddy's
//! certificate check and redirects requests as the host's AFWD record says.

use std::sync::Arc;

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{HOST, LOCATION},
        uri::Authority,
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

use afwd_core::{
    dns::{DnsConfig, ResolveError},
    docs::DocsConfig,
    pages::{self, respond},
    redirect::redirect_url,
    stats::{record_request, Stats},
};

#[derive(serde::Deserialize)]
struct CertificateQuery {
    domain: String,
}

struct EdgeState {
    dns: DnsConfig,
    docs: DocsConfig,
    stats: Option<Stats>,
}

pub fn router(dns: DnsConfig, docs: DocsConfig, stats: Option<Stats>) -> Router {
    let state = Arc::new(EdgeState { dns, docs, stats });
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
    State(state): State<Arc<EdgeState>>,
    Query(query): Query<CertificateQuery>,
) -> StatusCode {
    let domain = query.domain.trim_end_matches('.');
    if is_ip_address(domain) {
        return StatusCode::FORBIDDEN;
    }
    if state.docs.is_help_domain(domain) || state.docs.is_target_host(domain) {
        return StatusCode::OK;
    }

    match state.dns.resolve(domain).await {
        Ok(config) if config.request_certificate => StatusCode::OK,
        Ok(_) | Err(ResolveError::NotFound | ResolveError::Config(_)) => StatusCode::FORBIDDEN,
        Err(ResolveError::Dns(_)) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn forward(
    State(state): State<Arc<EdgeState>>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(host) = request_host(&headers) else {
        return (StatusCode::BAD_REQUEST, "host header required").into_response();
    };
    let record = |status: &str| record_request(state.stats.as_ref(), &host, status, &uri, &headers);
    if is_ip_address(&host) && uri.path() == "/" && uri.query().is_none() {
        // A bare address has no domain to forward, so it shows the landing page.
        return respond(StatusCode::OK, pages::Landing::new(&state.docs));
    }
    if !state.docs.is_help_domain(&host) && state.docs.is_target_host(&host) {
        // Domains point at the target host with a CNAME or ALIAS; visitors who open it
        // directly are sent to the help site.
        if let Some(help_url) = state.docs.help_url() {
            return (StatusCode::FOUND, [(LOCATION, help_url)]).into_response();
        }
    }

    match state.dns.resolve(&host).await {
        Ok(config) => {
            let Some(location) = redirect_url(
                &config,
                &host,
                uri.path_and_query().map_or("/", |value| value.as_str()),
            ) else {
                record("400");
                return (StatusCode::BAD_REQUEST, "invalid request URI").into_response();
            };
            let mut response = StatusCode::from_u16(config.status)
                .unwrap_or(StatusCode::FOUND)
                .into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            record(response.status().as_str());
            response
        }
        Err(error @ (ResolveError::NotFound | ResolveError::Config(_))) => {
            // Unknown hosts are not recorded, so forged Host headers cannot fill the database.
            let reason = match error {
                ResolveError::Config(error) => {
                    record("config-error");
                    Some(error.to_string())
                }
                _ => None,
            };
            respond(
                StatusCode::NOT_FOUND,
                pages::NotFound {
                    domain: host,
                    reason,
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
