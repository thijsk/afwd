use std::time::Duration;

use afwd::{
    config::parse_txt_record,
    dns::DnsConfig,
    docs::DocsConfig,
    http::{router, router_with_docs, router_with_stats},
    redirect::redirect_url,
    stats::Stats,
};
use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request, StatusCode},
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
async fn stats_api_rejects_unknown_token_and_is_limited_to_help_domain() {
    let app = router_with_stats(
        DnsConfig::new(Duration::from_secs(1)),
        DocsConfig::with_help_domain("afwd.nl"),
        Some(Stats::open(":memory:").unwrap()),
    );
    let request = |host: &str| {
        Request::builder()
            .uri("/api/stats/example.invalid")
            .header("host", host)
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap()
    };

    let response = app.clone().oneshot(request("afwd.nl")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app.oneshot(request("customer.invalid")).await.unwrap();
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
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

#[tokio::test]
async fn help_pages_are_counted_but_other_help_routes_are_not() {
    let stats = Stats::open(":memory:").unwrap();
    let app = router_with_stats(
        DnsConfig::new(Duration::from_secs(1)),
        DocsConfig::with_help_domain("help.example"),
        Some(stats.clone()),
    );
    for (host, path) in [
        ("help.example", "/"),
        ("help.example", "/stats"),
        ("help.example", "/.well-known/security.txt"),
        ("help.example", "/api/stats/example.com"),
        ("127.0.0.1", "/"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("host", host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if path == "/" || path == "/stats" {
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    stats.flush().await.unwrap();
    let report = stats.query("help.example".to_owned()).await.unwrap();
    assert_eq!(
        report.hits.iter().map(|(_, _, count)| count).sum::<i64>(),
        2
    );
    assert_eq!(report.paths.len(), 2);
    assert!(report.paths.contains(&("/".to_owned(), 1)));
    assert!(report.paths.contains(&("/stats".to_owned(), 1)));
    assert!(stats
        .query("127.0.0.1".to_owned())
        .await
        .unwrap()
        .hits
        .is_empty());
}

#[tokio::test]
async fn security_txt_is_served_only_on_help_domain() {
    let app = router_with_docs(
        DnsConfig::new(Duration::from_secs(1)),
        DocsConfig::with_help_domain("afwd.nl"),
    );
    let request = |host: &str| {
        Request::builder()
            .uri("/.well-known/security.txt")
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    };

    let response = app.clone().oneshot(request("afwd.nl")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.starts_with("Contact: mailto:info@trilobit.nl\nExpires: "));
    let expires = body
        .trim()
        .strip_prefix("Contact: mailto:info@trilobit.nl\nExpires: ")
        .unwrap();
    assert!(
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .is_ok()
    );

    let response = app.oneshot(request("customer.invalid")).await.unwrap();
    assert_ne!(response.status(), StatusCode::OK);
}
