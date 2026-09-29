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
    match state.dns.resolve(query.domain.trim_end_matches('.')).await {
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
    if is_root && (host.parse::<std::net::IpAddr>().is_ok() || state.docs.is_help_domain(&host)) {
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

fn request_host(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(HOST)?.to_str().ok()?;
    let authority = value.parse::<Authority>().ok()?;
    Some(authority.host().trim_end_matches('.').to_owned())
}
