use crate::config::ForwardingConfig;
use url::Url;

pub fn redirect_url(config: &ForwardingConfig, host: &str, source_uri: &str) -> Option<String> {
    let source = Url::parse(&format!("http://placeholder.invalid{source_uri}")).ok()?;
    let mut destination = config.destination.clone();

    if config.preserve_query {
        destination.set_query(source.query());
    } else if config.append_domain {
        let domain = url::form_urlencoded::byte_serialize(host.as_bytes()).collect::<String>();
        return Some(match destination.as_str().split_once('#') {
            Some((prefix, fragment)) => format!("{prefix}{domain}#{fragment}"),
            None => format!("{destination}{domain}"),
        });
    } else {
        destination.set_query(None);
    }

    Some(destination.into())
}
