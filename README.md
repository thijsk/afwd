# AFWD

Rust implementation of the AFWD DNS-based web forwarding service.

This project is based on the web forwarding specification published at [afwd.uk](https://afwd.uk/).

The service reads `v=afwd1` TXT records and returns HTTP redirects. HTTPS certificates are provided automatically.

## Caddy

The Docker image runs Rust and Caddy together. Rust listens privately on port `9000`. Caddy provides public HTTP and HTTPS access on ports `80` and `443`. A record with `cert=no` returns `403` and does not receive a certificate.

A forwarding domain points at the service in one of three ways:

- A subdomain uses a CNAME to the target host (`AFWD_TARGET_HOST`, default `fwd.<help domain>`).
- A root domain uses an ALIAS, ANAME or flattened CNAME to the target host, if its DNS provider supports one.
- Any domain can use A/AAAA records with the public service addresses.

With a CNAME or ALIAS, the service can move to new addresses without domain owners changing their DNS: only the target host's A/AAAA records change. The target host must not have a `v=afwd1` TXT record of its own, or every CNAME to it without a configuration would use that record. Requests to the target host itself redirect to the help domain. Set `AFWD_TARGET_HOST` to an empty value to offer only A/AAAA records.

Each forwarding configuration is a TXT record beginning with:

```text
v=afwd1 dest=https://example.net/ preserve=y type=302
```

The service uses the first `v=afwd1` record it finds at `_afwd.<host>`, at `<host>` itself (as in the afwd.uk specification, following CNAMEs), and then at `_afwd.<target>` and `<target>` for the target of a CNAME at `<host>`. The `_afwd.` name is our extension: a name with a CNAME cannot have its own TXT record, so `go.example.com CNAME fwd.afwd.nl` is configured at `_afwd.go.example.com`. If the `_afwd.` lookup fails but the record on the name is found, that record is used, so existing domains keep working.

With `preserve=y` the request path and query string are added to the destination, so `/blog/post?x=1` goes to `https://example.net/blog/post?x=1`. Without it, every request goes to the destination as written.

Set `AFWD_PUBLIC_IPV4` and `AFWD_PUBLIC_IPV6` to comma-separated public addresses. The help page uses these values in its DNS examples. Set `AFWD_HELP_DOMAIN` to change the domain that shows the help page; it defaults to `afwd.nl`.

The help domain serves a landing page at `/` and the full documentation at `/docs`. The landing page shows live totals from `GET /api/summary` (requests and domains over the last 90 days, excluding the help domain) and has a record builder and a domain checker. The checker calls `GET https://<help domain>/api/check/example.com`, which reports the domain's A/AAAA addresses (and whether they match `AFWD_PUBLIC_IPV4`/`AFWD_PUBLIC_IPV6` or the target host's current addresses), its CNAME target, its `v=afwd1` record and the name it was found at, any error in that record, and the resulting redirect. When a domain points at the service without a usable record, the 404 page shows the reason and links to the checker.

The HTML pages are askama templates in `templates/`. They are compiled into the binary.

The help domain also serves `/.well-known/security.txt`, with Trilobit's published contact address (`info@trilobit.nl`) and a rolling one-year expiry.

Run the complete service with Docker:

```powershell
docker run --rm --name afwd -e AFWD_PUBLIC_IPV4=YOUR_PUBLIC_IPV4 -e AFWD_PUBLIC_IPV6=YOUR_PUBLIC_IPV6 -e AFWD_HELP_DOMAIN=afwd.nl -p 80:8080 -p 443:8443 -v afwd-data:/data -v afwd-config:/config -v afwd-stats:/stats afwd:local
```

View HTTP access logs with `docker logs -f afwd`.

## Usage statistics

The service counts requests for each domain that has an AFWD TXT record. It also counts visits to `/`, `/docs` and `/stats` on the help domain, but not `/domains`, the `/api/` endpoints, or security.txt. It counts hits by hour and status, paths, and referrer domains. It does not store IP addresses, user agents, or query strings. The statistics are kept for 90 days. The public `/domains` page lists the 100 domains with the most requests during that period, excluding the help domain.

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

CI also checks that every dependency uses a permissive license, with `cargo deny check licenses` and the allow list in `deny.toml`.

## License

Copyright © 2026 Trilobit.

afwd is licensed under the GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE). If you run a modified version as a network service, the AGPL requires you to offer its source code to the users of that service.

Trilobit may also offer afwd under other terms, including closed source. To keep that possible, contributions are accepted under the Contributor License Agreement in [CONTRIBUTING.md](CONTRIBUTING.md), and dependencies must use permissive licenses.
