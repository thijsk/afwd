//! The afwd1 record syntax and the redirect it produces.

use afwd_core::{config::parse_txt_record, redirect::redirect_url};

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
fn preserves_source_path_and_query() {
    let config =
        parse_txt_record("v=afwd1 preserve=y type=308 dest=https://www.example.net/").unwrap();

    assert_eq!(config.status, 308);
    for (source, expected) in [
        ("/", "https://www.example.net/"),
        ("/query-string/", "https://www.example.net/query-string/"),
        ("/path/?x=1&y=2", "https://www.example.net/path/?x=1&y=2"),
        ("/a%20b/c", "https://www.example.net/a%20b/c"),
        ("/?x=1", "https://www.example.net/?x=1"),
    ] {
        assert_eq!(
            redirect_url(&config, "example.com", source).unwrap(),
            expected
        );
    }
}

#[test]
fn preserved_path_is_appended_to_destination_path() {
    let with_slash =
        parse_txt_record("v=afwd1 preserve=y dest=https://www.example.net/base/").unwrap();
    let without_slash =
        parse_txt_record("v=afwd1 preserve=y dest=https://www.example.net/base").unwrap();

    for config in [&with_slash, &without_slash] {
        assert_eq!(
            redirect_url(config, "example.com", "/a/b?x=1").unwrap(),
            "https://www.example.net/base/a/b?x=1"
        );
        // Dot segments cannot climb out of the destination's base path.
        assert_eq!(
            redirect_url(config, "example.com", "/../../secret").unwrap(),
            "https://www.example.net/base/secret"
        );
    }
    assert_eq!(
        redirect_url(&with_slash, "example.com", "//other.example/x").unwrap(),
        "https://www.example.net/base//other.example/x"
    );
}

#[test]
fn appends_domain_to_existing_destination_query() {
    let config = parse_txt_record(
        "v=afwd1 type=perm append=y dest=https://www.example.net/?source=afwd&host=",
    )
    .unwrap();

    assert_eq!(config.status, 301);
    assert_eq!(
        redirect_url(&config, "example.com", "/").unwrap(),
        "https://www.example.net/?source=afwd&host=example.com"
    );
}

#[test]
fn appends_domain_to_destination_path() {
    let config =
        parse_txt_record("v=afwd1 type=perm append=y dest=https://www.example.net/for/").unwrap();

    assert_eq!(
        redirect_url(&config, "example.com", "/").unwrap(),
        "https://www.example.net/for/example.com"
    );
}

#[test]
fn appends_domain_before_destination_fragment() {
    let config =
        parse_txt_record("v=afwd1 append=y dest=https://www.example.net/?host=#section").unwrap();

    assert_eq!(
        redirect_url(&config, "example.com", "/").unwrap(),
        "https://www.example.net/?host=example.com#section"
    );
}

#[test]
fn preserve_overrides_append() {
    let config =
        parse_txt_record("v=afwd1 preserve=y append=y dest=https://www.example.net/").unwrap();

    assert_eq!(
        redirect_url(&config, "example.com", "/query-string/?source=1").unwrap(),
        "https://www.example.net/query-string/?source=1"
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
