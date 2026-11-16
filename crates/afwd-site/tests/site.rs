//! The help site, which the proxy sends only the help domain.

use std::time::Duration;

use afwd_core::{dns::DnsConfig, docs::DocsConfig, stats::Stats};
use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request, StatusCode},
    Router,
};
use tower::ServiceExt;

fn app(docs: DocsConfig, stats: Option<Stats>) -> Router {
    afwd_site::router(DnsConfig::new(Duration::from_secs(60)), docs, stats)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("host", "afwd.nl")
        .body(Body::empty())
        .unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn health_endpoint_is_available() {
    let response = app(DocsConfig::default(), None)
        .oneshot(get("/healthz"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn landing_page_is_served() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("/"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_path_returns_not_found() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("/nope"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = body_text(response).await;
    assert!(body.contains("Page not found"));
    assert!(!body.contains("Forwarding not configured"));
}

#[tokio::test]
async fn stats_api_rejects_unknown_token() {
    let response = app(
        DocsConfig::with_help_domain("afwd.nl"),
        Some(Stats::open(":memory:").unwrap()),
    )
    .oneshot(
        Request::builder()
            .uri("/api/stats/example.invalid")
            .header("host", "afwd.nl")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["www-authenticate"], "Bearer");
}

#[tokio::test]
async fn domain_leaderboard_is_public_and_excludes_the_help_domain() {
    let stats = Stats::open(":memory:").unwrap();
    stats.record("popular.example", "302", "/", None);
    stats.record("help.example", "200", "/", None);
    stats.flush().await.unwrap();
    let app = app(DocsConfig::with_help_domain("help.example"), Some(stats));

    let response = app.clone().oneshot(get("/domains")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response)
        .await
        .contains("100 most active domains"));

    let response = app.oneshot(get("/api/domains")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("popular.example"));
    assert!(!body.contains("help.example"));
}

#[tokio::test]
async fn help_pages_are_counted_but_other_help_routes_are_not() {
    let stats = Stats::open(":memory:").unwrap();
    let app = app(
        DocsConfig::with_help_domain("help.example"),
        Some(stats.clone()),
    );
    for path in [
        "/",
        "/stats",
        "/docs",
        "/api/summary",
        "/.well-known/security.txt",
        "/api/stats/example.com",
    ] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        if matches!(path, "/" | "/stats" | "/docs" | "/api/summary") {
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    stats.flush().await.unwrap();
    let report = stats.query("help.example".to_owned()).await.unwrap();
    assert_eq!(
        report.hits.iter().map(|(_, _, count)| count).sum::<i64>(),
        3
    );
    assert_eq!(report.paths.len(), 3);
    assert!(report.paths.contains(&("/".to_owned(), 1)));
    assert!(report.paths.contains(&("/stats".to_owned(), 1)));
    assert!(report.paths.contains(&("/docs".to_owned(), 1)));
}

#[tokio::test]
async fn security_txt_has_contact_and_expiry() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("/.well-known/security.txt"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    let body = body_text(response).await;
    let expires = body
        .trim()
        .strip_prefix("Contact: mailto:info@trilobit.nl\nExpires: ")
        .unwrap();
    assert!(
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .is_ok()
    );
}

#[tokio::test]
async fn robots_txt_disallows_the_api() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("/robots.txt"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        body_text(response).await,
        "User-agent: *\nDisallow: /api/\n\nSitemap: https://afwd.nl/sitemap.xml\n"
    );
}

#[tokio::test]
async fn sitemap_lists_the_help_pages() {
    let response = app(DocsConfig::with_help_domain("afwd.nl"), None)
        .oneshot(get("/sitemap.xml"))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "application/xml; charset=utf-8"
    );
    let body = body_text(response).await;
    for url in [
        "https://afwd.nl/",
        "https://afwd.nl/docs",
        "https://afwd.nl/spec",
        "https://afwd.nl/stats",
        "https://afwd.nl/domains",
    ] {
        assert!(body.contains(&format!("<loc>{url}</loc>")), "{url}");
    }

    // Without a help domain there are no absolute addresses to list.
    let response = app(DocsConfig::default(), None)
        .oneshot(get("/sitemap.xml"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pages_name_their_canonical_address() {
    let app = app(DocsConfig::with_help_domain("afwd.nl"), None);
    for (path, canonical) in [
        ("/", "https://afwd.nl/"),
        ("/docs", "https://afwd.nl/docs"),
        ("/spec", "https://afwd.nl/spec"),
        ("/stats", "https://afwd.nl/stats"),
        ("/domains", "https://afwd.nl/domains"),
    ] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        let body = body_text(response).await;
        assert!(
            body.contains(&format!("<link rel=\"canonical\" href=\"{canonical}\">")),
            "{path}"
        );
    }
}

#[tokio::test]
async fn domain_check_reports_missing_records() {
    let app = app(DocsConfig::with_help_domain("afwd.nl"), None);

    let response = app
        .clone()
        .oneshot(get("/api/check/Customer.invalid."))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert_eq!(body["domain"], "customer.invalid");
    assert_eq!(body["addresses"], serde_json::json!([]));
    assert!(body["record"].is_null());

    let response = app.oneshot(get("/api/check/127.0.0.1")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn domain_check_reports_cname_and_record_name() {
    let response = app(
        DocsConfig::with_help_domain("afwd.nl").with_target_host("fwd.afwd.nl"),
        None,
    )
    .oneshot(get("/api/check/customer.invalid"))
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(response).await).unwrap();
    assert!(body["cname"].is_null());
    assert!(body["record_name"].is_null());
}
