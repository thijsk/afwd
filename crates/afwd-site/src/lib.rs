//! The help site (afwd.nl): the landing page, docs, stats pages and their APIs. The proxy
//! sends only the help domain here, so the routes do not look at the Host header.

pub mod check;
pub mod spec;

use std::{sync::Arc, time::Duration as StdDuration};

use axum::{
    extract::{Path, State},
    http::{
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, REFERER, RETRY_AFTER, WWW_AUTHENTICATE,
        },
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tokio::sync::Semaphore;

use afwd_core::{
    dns::DnsConfig,
    docs::DocsConfig,
    pages::{self, respond},
    stats::Stats,
};

use crate::check::{check, normalize_domain};

/// Domain checks that may run at the same time. More are refused, not queued, so a flood
/// of checks cannot pile up slow DNS lookups.
const MAX_CONCURRENT_CHECKS: usize = 16;
const CHECK_TIMEOUT: StdDuration = StdDuration::from_secs(4);

struct SiteState {
    dns: DnsConfig,
    docs: DocsConfig,
    stats: Option<Stats>,
    checks: Arc<Semaphore>,
}

type AppState = State<Arc<SiteState>>;

pub fn router(dns: DnsConfig, docs: DocsConfig, stats: Option<Stats>) -> Router {
    let state = Arc::new(SiteState {
        dns,
        docs,
        stats,
        checks: Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS)),
    });
    Router::new()
        .route("/", get(landing))
        .route("/docs", get(docs_page))
        .route("/spec", get(spec_page))
        .route("/spec.txt", get(spec_text))
        .route("/stats", get(stats_page))
        .route("/domains", get(domains_page))
        .route("/api/summary", get(summary_api))
        .route("/api/domains", get(domains_api))
        .route("/api/check/{domain}", get(check_api))
        .route("/api/stats/{domain}", get(stats_api))
        .route("/.well-known/security.txt", get(security_txt))
        .route("/robots.txt", get(robots_txt))
        .route("/healthz", get(health))
        .fallback(not_found)
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// Counts a visit to a help page under the help domain.
fn count(state: &SiteState, path: &str, headers: &HeaderMap) {
    if let (Some(stats), Some(domain)) = (&state.stats, state.docs.help_domain()) {
        let referer = headers.get(REFERER).and_then(|value| value.to_str().ok());
        stats.record(domain, "200", path, referer);
    }
}

async fn landing(State(state): AppState, headers: HeaderMap) -> Response {
    count(&state, "/", &headers);
    respond(StatusCode::OK, pages::Landing::new(&state.docs))
}

async fn docs_page(State(state): AppState, headers: HeaderMap) -> Response {
    count(&state, "/docs", &headers);
    respond(StatusCode::OK, pages::Docs::new(&state.docs))
}

async fn spec_page(State(state): AppState, headers: HeaderMap) -> Response {
    count(&state, "/spec", &headers);
    respond(
        StatusCode::OK,
        pages::SpecPage {
            html: spec::SPEC.html(),
        },
    )
}

async fn spec_text() -> Response {
    plain_text(spec::SPEC.text())
}

async fn stats_page(State(state): AppState, headers: HeaderMap) -> Response {
    count(&state, "/stats", &headers);
    respond(StatusCode::OK, pages::StatsPage)
}

async fn domains_page() -> Response {
    respond(StatusCode::OK, pages::DomainsPage)
}

async fn not_found(State(state): AppState) -> Response {
    respond(
        StatusCode::NOT_FOUND,
        pages::NotFound {
            domain: state.docs.help_domain().unwrap_or_default().to_owned(),
            reason: None,
            help_url: state.docs.help_url(),
        },
    )
}

fn plain_text(body: impl IntoResponse) -> Response {
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

async fn security_txt() -> Response {
    let expires = (OffsetDateTime::now_utc() + Duration::days(365))
        .format(&Rfc3339)
        .unwrap();
    plain_text(format!(
        "Contact: mailto:info@trilobit.nl\nExpires: {expires}\n"
    ))
}

async fn robots_txt() -> Response {
    plain_text("User-agent: *\nDisallow: /api/\n")
}

async fn summary_api(State(state): AppState) -> Response {
    let Some(stats) = &state.stats else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let excluded_host = state.docs.help_domain().unwrap_or_default();
    match stats.summary(excluded_host).await {
        // Shown on the landing page, so browsers may reuse it for a few minutes.
        Ok(summary) => ([(CACHE_CONTROL, "public, max-age=300")], Json(summary)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "summary query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn domains_api(State(state): AppState) -> Response {
    let Some(stats) = &state.stats else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let excluded_host = state.docs.help_domain().unwrap_or_default();
    match stats.top_domains(excluded_host).await {
        Ok(domains) => ([(CACHE_CONTROL, "no-store")], Json(domains)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "domain leaderboard query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn check_api(State(state): AppState, Path(domain): Path<String>) -> Response {
    check_domain(&state, &domain).await
}

async fn check_domain(state: &SiteState, domain: &str) -> Response {
    let Some(domain) = normalize_domain(domain) else {
        return (StatusCode::BAD_REQUEST, "invalid domain name").into_response();
    };
    let Ok(_permit) = state.checks.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(RETRY_AFTER, "5")],
            "Too many checks are running. Try again in a few seconds.",
        )
            .into_response();
    };
    let public = state.docs.public_addresses();
    let lookup = check(&state.dns, &public, state.docs.target_host(), domain);
    match tokio::time::timeout(CHECK_TIMEOUT, lookup).await {
        Ok(Ok(result)) => ([(CACHE_CONTROL, "no-store")], Json(result)).into_response(),
        Ok(Err(error)) => {
            tracing::debug!(%error, "domain check lookup failed");
            (StatusCode::SERVICE_UNAVAILABLE, "DNS lookup failed").into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "DNS lookup timed out").into_response(),
    }
}

/// A 401 must say which authentication scheme to use (RFC 9110, Section 11.6.1).
fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, "Bearer")]).into_response()
}

async fn stats_api(
    State(state): AppState,
    headers: HeaderMap,
    Path(domain): Path<String>,
) -> Response {
    let Some(stats) = &state.stats else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let Some(token) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token.trim())
    else {
        return unauthorized();
    };
    let hash = Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Plain comparison is fine: the expected hash is public in DNS.
    if !state.dns.stats_hashes(&domain).await.contains(&hash) {
        return unauthorized();
    }
    match stats.query(domain).await {
        Ok(report) => ([(CACHE_CONTROL, "no-store")], Json(report)).into_response(),
        Err(error) => {
            tracing::warn!(%error, "stats query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{check_domain, SiteState};
    use afwd_core::{dns::DnsConfig, docs::DocsConfig};
    use axum::http::StatusCode;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn domain_checks_are_refused_when_all_slots_are_busy() {
        let state = SiteState {
            dns: DnsConfig::new(Duration::from_secs(1)),
            docs: DocsConfig::default(),
            stats: None,
            checks: Arc::new(Semaphore::new(0)),
        };
        let response = check_domain(&state, "example.com").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "5");
    }
}
