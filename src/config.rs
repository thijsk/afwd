use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardingConfig {
    pub destination: Url,
    pub preserve_query: bool,
    pub append_domain: bool,
    pub status: u16,
    pub request_certificate: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("TXT record does not start with v=afwd1")]
    UnsupportedVersion,
    #[error("TXT record is missing dest")]
    MissingDestination,
    #[error("destination must use http or https")]
    InvalidDestination,
    #[error("invalid value for {0}")]
    InvalidValue(String),
    #[error("unsupported token {0}")]
    UnsupportedToken(String),
}

pub fn parse_txt_record(record: &str) -> Result<ForwardingConfig, ConfigError> {
    let mut tokens = record.split_whitespace();
    if tokens.next() != Some("v=afwd1") {
        return Err(ConfigError::UnsupportedVersion);
    }

    let mut destination = None;
    let mut preserve_query = false;
    let mut append_domain = false;
    let mut status = 302;
    let mut request_certificate = true;

    for token in tokens {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| ConfigError::UnsupportedToken(token.to_owned()))?;
        match key {
            "dest" => {
                let parsed = Url::parse(value).map_err(|_| ConfigError::InvalidDestination)?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                    return Err(ConfigError::InvalidDestination);
                }
                destination = Some(parsed);
            }
            "preserve" => preserve_query = parse_bool(key, value)?,
            "append" => append_domain = parse_bool(key, value)?,
            "type" => {
                status = match value {
                    "perm" => 301,
                    "temp" => 302,
                    "301" | "302" | "307" | "308" => value.parse().expect("validated status"),
                    _ => return Err(ConfigError::InvalidValue(key.to_owned())),
                };
            }
            "cert" => {
                if value == "no" {
                    request_certificate = false;
                } else {
                    return Err(ConfigError::InvalidValue(key.to_owned()));
                }
            }
            _ => return Err(ConfigError::UnsupportedToken(key.to_owned())),
        }
    }

    Ok(ForwardingConfig {
        destination: destination.ok_or(ConfigError::MissingDestination)?,
        preserve_query,
        append_domain,
        status,
        request_certificate,
    })
}

fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value {
        "y" => Ok(true),
        "n" => Ok(false),
        _ => Err(ConfigError::InvalidValue(key.to_owned())),
    }
}
