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

#[test]
fn destination_query_is_kept_and_merged_with_the_request_query() {
    let plain = parse_txt_record("v=afwd1 dest=https://www.example.net/?ref=afwd").unwrap();
    assert_eq!(
        redirect_url(&plain, "example.com", "/page?x=1").unwrap(),
        "https://www.example.net/?ref=afwd"
    );

    let preserve =
        parse_txt_record("v=afwd1 preserve=y dest=https://www.example.net/shop?ref=afwd#top")
            .unwrap();
    for (source, expected) in [
        ("/a?x=1", "https://www.example.net/shop/a?ref=afwd&x=1#top"),
        ("/a", "https://www.example.net/shop/a?ref=afwd#top"),
        ("/a?", "https://www.example.net/shop/a?ref=afwd#top"),
    ] {
        assert_eq!(
            redirect_url(&preserve, "example.com", source).unwrap(),
            expected
        );
    }
}

#[test]
fn repeated_parameters_use_the_last_occurrence() {
    let config = parse_txt_record(
        "v=afwd1 dest=https://a.example/ type=301 dest=https://b.example/ type=307",
    )
    .unwrap();
    assert_eq!(config.destination.as_str(), "https://b.example/");
    assert_eq!(config.status, 307);
}

#[test]
fn invalid_records_are_rejected() {
    for record in [
        "v=afwd1",
        "v=afwd1 preserve=y",
        "v=afwd1 dest=ftp://example.net/",
        "v=afwd1 dest=https://",
        "v=afwd1 dest=not-a-url",
        "v=afwd1 dest=https://example.net/ www=y",
        "v=afwd1 dest=https://example.net/ preserve",
        "v=afwd1 dest=https://example.net/ type=303",
        "v=afwd1 dest=https://example.net/ cert=yes",
        // Names and values are case-sensitive.
        "v=afwd1 dest=https://example.net/ preserve=Y",
        "v=afwd1 DEST=https://example.net/",
        "v=afwd1 dest=https://example.net/ type=PERM",
        "V=AFWD1 dest=https://example.net/",
    ] {
        assert!(parse_txt_record(record).is_err(), "{record}");
    }
}

#[test]
fn only_space_and_tab_separate_tokens() {
    let config = parse_txt_record("v=afwd1\tpreserve=y  dest=https://example.net/ \t").unwrap();
    assert!(config.preserve_query);

    // A no-break space is part of the token, so it ends up in the URL.
    let config = parse_txt_record("v=afwd1 dest=https://example.net/\u{a0}preserve=y").unwrap();
    assert!(!config.preserve_query);
    assert_eq!(
        config.destination.as_str(),
        "https://example.net/%C2%A0preserve=y"
    );
}
