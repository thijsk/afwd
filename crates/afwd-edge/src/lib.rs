//! The forwarding service: every host except the help domain. It answers Caddy's
//! certificate check and redirects requests as the host's AFWD record says.

use std::{net::IpAddr, sync::Arc};

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{CACHE_CONTROL, HOST, LOCATION},
        uri::Authority,
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
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

    // Section 6 of the specification. Every refusal is final for now; Caddy asks again
    // at the next TLS connection for the name.
    match state.dns.resolve_for_certificate(domain).await {
        Ok(config) if config.request_certificate => {}
        Ok(_) | Err(ResolveError::NotFound | ResolveError::Config(_)) => {
            return StatusCode::FORBIDDEN
        }
        Err(ResolveError::Dns(_) | ResolveError::Incomplete) => {
            return StatusCode::SERVICE_UNAVAILABLE
        }
    }
    // The certificate authority validates over HTTP at the name's addresses, so a name
    // that points elsewhere would only fail validation.
    let mut ours = state.docs.public_addresses();
    if let Some(target) = state.docs.target_host() {
        ours.extend(state.dns.addresses(target).await.unwrap_or_default());
    }
    match state.dns.addresses(domain).await {
        Ok(addresses) if points_at(&addresses, &ours) => {}
        Ok(_) => return StatusCode::FORBIDDEN,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE,
    }
    if let Some(stats) = &state.stats {
        match stats.admit_certificate(domain).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(domain, "too many new certificate names for this domain");
                return StatusCode::FORBIDDEN;
            }
            Err(error) => {
                tracing::warn!(%error, domain, "certificate admission failed");
                return StatusCode::SERVICE_UNAVAILABLE;
            }
        }
    }
    StatusCode::OK
}

fn redirect(status: u16, location: &str) -> Response {
    let mut response = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::FOUND)
        .into_response();
    response
        .headers_mut()
        .insert(LOCATION, HeaderValue::from_str(location).unwrap());
    if matches!(status, 301 | 308) {
        // Browsers keep permanent redirects indefinitely unless told otherwise, which
        // would outlast any change to the record.
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
    }
    response
}

/// Whether every address of a name is one of `ours`. With nothing to compare against,
/// every name passes.
fn points_at(addresses: &[IpAddr], ours: &[IpAddr]) -> bool {
    ours.is_empty() || !addresses.is_empty() && addresses.iter().all(|a| ours.contains(a))
}

async fn forward(
    State(state): State<Arc<EdgeState>>,
    method: Method,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let Some(host) = request_host(&uri, &headers) else {
        return (StatusCode::BAD_REQUEST, "host header required").into_response();
    };
    // CONNECT and `OPTIONS *` do not name a resource that can be forwarded.
    if method == Method::CONNECT || !uri.path().starts_with('/') {
        return (StatusCode::BAD_REQUEST, "unsupported request target").into_response();
    }
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
            let response = redirect(config.status, &location);
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
        Err(ResolveError::Dns(_) | ResolveError::Incomplete) => {
            (StatusCode::SERVICE_UNAVAILABLE, "DNS lookup failed").into_response()
        }
    }
}

fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

/// The host of an absolute-form target (and of HTTP/2's `:authority`), or else of the
/// Host header field, as in Section 3.2.2 of RFC 9112.
fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    let authority = match uri.authority() {
        Some(authority) => authority.clone(),
        None => headers
            .get(HOST)?
            .to_str()
            .ok()?
            .parse::<Authority>()
            .ok()?,
    };
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    Some(host.trim_end_matches('.').to_owned())
}

#[cfg(test)]
mod tests {
    use super::{points_at, redirect, request_host};
    use axum::http::{header::HOST, HeaderMap, HeaderValue, Uri};

    #[test]
    fn ip_addresses_are_not_treated_as_domain_names() {
        assert!(super::is_ip_address("127.0.0.1"));
        assert!(super::is_ip_address("::1"));
        assert!(!super::is_ip_address("example.com"));
    }

    #[test]
    fn strips_port_from_host_header() {
        let origin = Uri::from_static("/");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("127.0.0.1:8080"));
        assert_eq!(
            request_host(&origin, &headers),
            Some("127.0.0.1".to_owned())
        );

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("[::1]:8443"));
        assert_eq!(request_host(&origin, &headers), Some("::1".to_owned()));
    }

    #[test]
    fn absolute_form_target_wins_over_the_host_header() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("other.example"));
        let uri = Uri::from_static("http://Example.com.:8080/page");
        assert_eq!(request_host(&uri, &headers), Some("Example.com".to_owned()));
    }

    #[test]
    fn permanent_redirects_may_be_cached_for_an_hour() {
        for (status, cached) in [(301, true), (308, true), (302, false), (307, false)] {
            let response = redirect(status, "https://example.net/");
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["location"], "https://example.net/");
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .map(|v| v.to_str().unwrap()),
                cached.then_some("max-age=3600"),
                "{status}"
            );
        }
    }

    #[test]
    fn certificates_need_every_address_to_be_ours() {
        let ours = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let elsewhere = "198.51.100.9".parse().unwrap();
        assert!(points_at(&ours, &ours));
        assert!(points_at(&ours[..1], &ours));
        // A leftover AAAA record elsewhere fails HTTP validation for the whole name.
        assert!(!points_at(&[ours[0], elsewhere], &ours));
        assert!(!points_at(&[], &ours));
        // Without configured addresses there is nothing to compare against.
        assert!(points_at(&[elsewhere], &[]));
    }
}
