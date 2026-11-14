use crate::config::ForwardingConfig;
use url::Url;

pub fn redirect_url(config: &ForwardingConfig, host: &str, source_uri: &str) -> Option<String> {
    let source = Url::parse(&format!("http://placeholder.invalid{source_uri}")).ok()?;
    let mut destination = config.destination.clone();

    if config.preserve_query {
        // The parser has removed the dot segments from the source path, so `..` cannot
        // climb out of the destination's base path. Percent-encoded dots (`%2e%2e`) are
        // kept as they are; the destination has to treat the path as untrusted.
        let path = format!(
            "{}{}",
            destination.path().trim_end_matches('/'),
            source.path()
        );
        destination.set_path(&path);
        // The destination's own query comes first, then the request's.
        let query = [destination.query(), source.query()]
            .into_iter()
            .flatten()
            .filter(|query| !query.is_empty())
            .collect::<Vec<_>>()
            .join("&");
        destination.set_query((!query.is_empty()).then_some(query.as_str()));
    } else if config.append_domain {
        let domain = url::form_urlencoded::byte_serialize(host.as_bytes()).collect::<String>();
        return Some(match destination.as_str().split_once('#') {
            Some((prefix, fragment)) => format!("{prefix}{domain}#{fragment}"),
            None => format!("{destination}{domain}"),
        });
    }

    Some(destination.into())
}
