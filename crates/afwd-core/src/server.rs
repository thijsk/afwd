//! Startup shared by the `afwd-edge` and `afwd-site` binaries.

use std::{net::SocketAddr, time::Duration};

use axum::Router;
use tokio::net::TcpListener;

use crate::{dns::DnsConfig, docs::DocsConfig, stats::Stats};

/// Builds a service's router from the shared configuration.
pub type App = fn(DnsConfig, DocsConfig, Option<Stats>) -> Router;

/// Reads the configuration from the environment and serves `app` on `AFWD_BIND`, or on
/// `default_bind` when that is not set.
pub async fn run(
    name: &str,
    default_bind: &str,
    app: App,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let address: SocketAddr = std::env::var("AFWD_BIND")
        .unwrap_or_else(|_| default_bind.to_owned())
        .parse()?;
    let dns = DnsConfig::new(Duration::from_secs(60));
    let docs = DocsConfig::from_env();
    let stats = Stats::open(
        &std::env::var("AFWD_STATS_DB").unwrap_or_else(|_| "afwd-stats.db".to_owned()),
    )?;
    let flusher = stats.clone();
    // ponytail: up to 60s of counts are lost on shutdown
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(error) = flusher.flush().await {
                tracing::warn!(%error, "stats flush failed");
            }
        }
    });
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, service = name, "AFWD service listening");
    axum::serve(listener, app(dns, docs, Some(stats))).await?;
    Ok(())
}
