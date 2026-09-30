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

Set `AFWD_PUBLIC_IPV4` and `AFWD_PUBLIC_IPV6` to comma-separated public addresses. The help page uses these values in its DNS examples. Set `AFWD_HELP_DOMAIN` to change the domain that shows the help page; it defaults to `afwd.nl`.

The help domain also serves `/.well-known/security.txt`, with Trilobit's published contact address (`info@trilobit.nl`) and a rolling one-year expiry.

Run the complete service with Docker:

```powershell
docker run --rm --name afwd -e AFWD_PUBLIC_IPV4=YOUR_PUBLIC_IPV4 -e AFWD_PUBLIC_IPV6=YOUR_PUBLIC_IPV6 -e AFWD_HELP_DOMAIN=afwd.nl -p 80:8080 -p 443:8443 -v afwd-data:/data -v afwd-config:/config -v afwd-stats:/stats afwd:local
```

View HTTP access logs with `docker logs -f afwd`.

## Usage statistics

The service counts requests for each domain that has an AFWD TXT record. It also counts visits to `/` and `/stats` on the help domain, but not its statistics API or security.txt. It counts hits by hour and status, paths, and referrer domains. It does not store IP addresses, user agents, or query strings. The statistics are kept for 90 days.

The statistics are stored in the SQLite file `AFWD_STATS_DB` (default `/stats/afwd.db` in Docker). Containers on the same host can share the `afwd-stats` volume.

To see the statistics for a domain, the owner opens `https://<help domain>/stats` and creates a token. Then the owner adds this TXT record:

```text
_afwd-stats.example.com. 3600 TXT "v=afwdstats1 h=<sha256 hex of token>"
```

The API is `GET https://<help domain>/api/stats/example.com` with the header `Authorization: Bearer <token>`. To rotate tokens, add more `h=` records. To remove access, delete the record.

## Local HTTPS testing

Add `127.0.0.1 afwd.nl` to your hosts file. Start the Rust service, then run Caddy with `deploy/Caddyfile.local`. Run `caddy trust` once so your browser trusts Caddy's local certificate.

## Development

```powershell
cargo test
cargo run
```
