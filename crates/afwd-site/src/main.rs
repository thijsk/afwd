//! The help site. Listens on `AFWD_BIND`, default `127.0.0.1:8081`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    afwd_core::server::run("site", "127.0.0.1:8081", afwd_site::router).await
}
