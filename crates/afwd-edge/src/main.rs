//! The forwarding service. Listens on `AFWD_BIND`, default `127.0.0.1:8080`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    afwd_core::server::run("edge", "127.0.0.1:8080", afwd_edge::router).await
}
