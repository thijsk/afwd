use std::sync::Arc;

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{HOST, LOCATION},
        uri::Authority,
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};

use crate::{
    dns::{DnsConfig, ResolveError},
    docs::{render, DocsConfig},
    redirect::redirect_url,
};

#[derive(serde::Deserialize)]
struct CertificateQuery {
    domain: String,
}

#[derive(Clone)]
pub struct AppState {
    pub dns: DnsConfig,
    pub docs: DocsConfig,
}

pub fn router(dns: DnsConfig) -> Router {
    router_with_docs(dns, DocsConfig::default())
}

pub fn router_with_docs(dns: DnsConfig, docs: DocsConfig) -> Router {
    let state = Arc::new(AppState { dns, docs });
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
        return axum::response::Html(render(&state.docs)).into_response();
    }

    match state.dns.resolve(&host).await {
        Ok(config) => {
            let Some(location) = redirect_url(
                &config,
                &host,
                uri.path_and_query().map_or("/", |value| value.as_str()),
            ) else {
                return (StatusCode::BAD_REQUEST, "invalid request URI").into_response();
            };
            let mut response = StatusCode::from_u16(config.status)
                .unwrap_or(StatusCode::FOUND)
                .into_response();
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_str(&location).unwrap());
            response
        }
        Err(ResolveError::NotFound | ResolveError::Config(_)) => {
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
    use super::{request_host};
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
