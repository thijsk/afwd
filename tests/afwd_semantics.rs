use std::time::Duration;

use afwd::{
    config::parse_txt_record,
    dns::DnsConfig,
    docs::DocsConfig,
    http::{router, router_with_docs},
    redirect::redirect_url,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[test]
fn parses_basic_record_with_defaults() {
    let config = parse_txt_record("v=afwd1 dest=https://www.example.net/").unwrap();

    assert_eq!(config.status, 302);
    assert_eq!(
        redirect_url(&config, "example.com", "/query-string/?x=1").unwrap(),
        "https://www.example.net/"
    );
}

#[test]
fn preserves_source_query() {
    let config =
        parse_txt_record("v=afwd1 preserve=y type=308 dest=https://www.example.net/").unwrap();

    assert_eq!(config.status, 308);
    assert_eq!(
        redirect_url(&config, "example.com", "/path/?x=1&y=2").unwrap(),
        "https://www.example.net/?x=1&y=2"
    );
}

#[test]
fn appends_domain_to_existing_destination_query() {
    let config =
        parse_txt_record("v=afwd1 type=perm append=y dest=https://www.example.net/?source=afwd")
            .unwrap();

    assert_eq!(config.status, 301);
    assert_eq!(
        redirect_url(&config, "example.com", "/").unwrap(),
        "https://www.example.net/?source=afwd&domain=example.com"
    );
}

#[test]
fn replaces_domain_placeholder_when_appending() {
    let config =
        parse_txt_record("v=afwd1 type=perm append=y dest=https://www.example.net/?domain=")
            .unwrap();

    assert_eq!(
        redirect_url(&config, "example.com", "/").unwrap(),
        "https://www.example.net/?domain=example.com"
    );
}

#[test]
fn preserve_overrides_append() {
    let config =
        parse_txt_record("v=afwd1 preserve=y append=y dest=https://www.example.net/").unwrap();

    assert_eq!(
        redirect_url(&config, "example.com", "/?source=1").unwrap(),
        "https://www.example.net/?source=1"
    );
}

#[test]
fn rejects_missing_destination_and_supports_cert_no() {
    assert!(parse_txt_record("v=afwd1 preserve=y").is_err());
    assert!(
        !parse_txt_record("v=afwd1 cert=no dest=https://www.example.net/")
            .unwrap()
            .request_certificate
    );
}

#[tokio::test]
async fn health_endpoint_is_available() {
    let response = router(DnsConfig::new(Duration::from_secs(1)))
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
    let response = router(DnsConfig::new(Duration::from_secs(1)))
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ip_root_request_returns_documentation() {
    let response = router(DnsConfig::new(Duration::from_secs(1)))
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "127.0.0.1:8080")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_help_domain_returns_documentation() {
    let response = router_with_docs(
        DnsConfig::new(Duration::from_secs(1)),
        DocsConfig::with_help_domain("afwd.nl"),
    )
    .oneshot(
        Request::builder()
            .uri("/")
            .header("host", "afwd.nl")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
