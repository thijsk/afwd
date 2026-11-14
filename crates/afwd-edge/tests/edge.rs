//! The forwarding service, which the proxy sends every host except the help domain.

use std::time::Duration;

use afwd_core::{dns::DnsConfig, docs::DocsConfig, stats::Stats};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;

fn app(docs: DocsConfig, stats: Option<Stats>) -> Router {
    afwd_edge::router(DnsConfig::new(Duration::from_secs(60)), docs, stats)
}

fn get(host: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("host", host)
        .body(Body::empty())
        .unwrap()
}

fn cert_check(domain: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/internal/cert-check?domain={domain}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn health_endpoint_is_available() {
    let response = app(DocsConfig::default(), None)
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn forwarding_requires_a_host_header() {
    let response = app(DocsConfig::default(), None)
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ip_root_request_returns_the_landing_page_and_is_not_counted() {
    let stats = Stats::open(":memory:").unwrap();
    let response = app(DocsConfig::with_help_domain("afwd.nl"), Some(stats.clone()))
        .oneshot(get("127.0.0.1:8080", "/"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    stats.flush().await.unwrap();
    assert!(stats
        .query("127.0.0.1".to_owned())
        .await
        .unwrap()
        .hits
        .is_empty());
}

#[tokio::test]
async fn help_site_routes_are_not_served_for_forwarded_domains() {
    let app = app(
        DocsConfig::with_help_domain("afwd.nl"),
        Some(Stats::open(":memory:").unwrap()),
    );
    for path in [
        "/api/stats/example.invalid",
        "/api/domains",
        "/api/summary",
        "/api/check/example.com",
        "/.well-known/security.txt",
        "/robots.txt",
    ] {
        let request = Request::builder()
            .uri(path)
            .header("host", "customer.invalid")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn host_without_afwd_record_returns_not_found() {
    let app = app(DocsConfig::default(), None);

    let response = app
        .clone()
        .oneshot(get("customer.invalid", "/"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app.oneshot(cert_check("customer.invalid")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn not_found_page_links_to_the_domain_check() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("customer.invalid", "/"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_text(response).await;
    assert!(body.contains("<strong>customer.invalid</strong>"));
    assert!(body.contains("https://afwd.nl/#check=customer.invalid"));
}

#[tokio::test]
async fn target_host_redirects_to_the_help_site_and_gets_a_certificate() {
    let app = app(
        DocsConfig::with_help_domain("afwd.nl").with_target_host("fwd.afwd.nl"),
        None,
    );

    let response = app
        .clone()
        .oneshot(get("FWD.afwd.nl", "/anything"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["location"], "https://afwd.nl/");

    // The proxy asks the edge about every certificate, the help domain's included.
    for domain in ["fwd.afwd.nl", "afwd.nl"] {
        let response = app.clone().oneshot(cert_check(domain)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{domain}");
    }
}
