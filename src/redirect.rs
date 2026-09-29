use crate::config::ForwardingConfig;
use url::Url;

pub fn redirect_url(config: &ForwardingConfig, host: &str, source_uri: &str) -> Option<String> {
    let source = Url::parse(&format!("http://placeholder.invalid{source_uri}")).ok()?;
    let mut destination = config.destination.clone();

    if config.preserve_query {
        destination.set_query(source.query());
    } else if config.append_domain {
        let mut query = destination.query().unwrap_or_default().to_owned();
        let domain = url::form_urlencoded::byte_serialize(host.as_bytes()).collect::<String>();
        if let Some(prefix) = query.strip_suffix("domain=") {
            query = format!("{prefix}domain={domain}");
        } else if query.is_empty() {
            query = format!("domain={domain}");
        } else {
            query.push('&');
            query.push_str("domain=");
            query.push_str(&domain);
        }
        destination.set_query(Some(&query));
    } else {
        destination.set_query(None);
    }

    Some(destination.into())
}
