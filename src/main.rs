use std::{net::SocketAddr, time::Duration};

use afwd::{dns::DnsConfig, docs::DocsConfig, http::router_with_stats, stats::Stats};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let address: SocketAddr = std::env::var("AFWD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
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
    tracing::info!(%address, "AFWD service listening");
    axum::serve(listener, router_with_stats(dns, docs, Some(stats))).await?;
    Ok(())
}
