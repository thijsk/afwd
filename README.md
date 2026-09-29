# AFWD

Rust implementation of the AFWD DNS-based web forwarding service.

This project is based on the web forwarding specification published at [afwd.uk](https://afwd.uk/).

The service reads `v=afwd1` TXT records and returns HTTP redirects. HTTPS certificates are provided automatically.

## Caddy

The Docker image runs Rust and Caddy together. Rust listens privately on port `9000`. Caddy provides public HTTP and HTTPS access on ports `80` and `443`. A record with `cert=no` returns `403` and does not receive a certificate.

The forwarding domain must point its A/AAAA records at the public service addresses. Subdomains can use CNAME records, and each forwarding configuration is a TXT record beginning with:

```text
v=afwd1 dest=https://example.net/ preserve=y type=302
```

Set `AFWD_PUBLIC_IPV4` and `AFWD_PUBLIC_IPV6` to comma-separated public addresses. The help page uses these values in its DNS examples.

Run the complete service with Docker:

```powershell
docker run --rm --name afwd -e AFWD_PUBLIC_IPV4=YOUR_PUBLIC_IPV4 -e AFWD_PUBLIC_IPV6=YOUR_PUBLIC_IPV6 -p 80:8080 -p 443:8443 -v afwd-data:/data -v afwd-config:/config afwd:local
```

## Local HTTPS testing

Add `127.0.0.1 afwd.nl` to your hosts file. Start the Rust service, then run Caddy with `deploy/Caddyfile.local`. Run `caddy trust` once so your browser trusts Caddy's local certificate.

## Development

```powershell
cargo test
cargo run
```
