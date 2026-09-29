use std::{net::SocketAddr, time::Duration};

use afwd::{dns::DnsConfig, docs::DocsConfig, http::router_with_docs};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let address: SocketAddr = std::env::var("AFWD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse()?;
    let dns = DnsConfig::new(Duration::from_secs(60));
    let docs = DocsConfig::from_env();
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "AFWD service listening");
    axum::serve(listener, router_with_docs(dns, docs)).await?;
    Ok(())
}
