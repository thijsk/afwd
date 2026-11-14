# AFWD

Rust implementation of the AFWD DNS-based web forwarding service.

This project is based on the web forwarding specification published at [afwd.uk](https://afwd.uk/).

The service reads `v=afwd1` TXT records and returns HTTP redirects. HTTPS certificates are provided automatically.

## Containers

The service runs as three containers:

- `proxy` runs Caddy. It provides public HTTP and HTTPS access and gets the certificates. It sends the help domain to `site` and every other host to `edge`.
- `edge` is the forwarding service (`crates/afwd-edge`). It answers Caddy's certificate check. A name gets a certificate only with a valid record without `cert=no`, when all its A/AAAA records point at the service (if `AFWD_PUBLIC_IPV4`/`AFWD_PUBLIC_IPV6` or the target host give addresses to compare against), and while its registrable domain has had fewer than 20 new certificate names in the past 7 days. The cap stops a wildcard record from letting anyone use up the domain's certificate limits; names that already forwarded traffic before the cap existed do not count.
- `site` is the help site (`crates/afwd-site`): the landing page, docs, checker and statistics.

`edge` and `site` listen on port `9000` inside the container network and are not published. Shared code lives in `crates/afwd-core`. `deploy/compose.yml` builds and runs all three.

A forwarding domain points at the service in one of three ways:

- A subdomain uses a CNAME to the target host (`AFWD_TARGET_HOST`, default `fwd.<help domain>`).
- A root domain uses an ALIAS, ANAME or flattened CNAME to the target host, if its DNS provider supports one.
- Any domain can use A/AAAA records with the public service addresses.

With a CNAME or ALIAS, the service can move to new addresses without domain owners changing their DNS: only the target host's A/AAAA records change. The target host must not have a `v=afwd1` TXT record of its own, or every CNAME to it without a configuration would use that record. Requests to the target host itself redirect to the help domain. Set `AFWD_TARGET_HOST` to an empty value to offer only A/AAAA records.

Each forwarding configuration is a TXT record beginning with:

```text
v=afwd1 dest=https://example.net/ preserve=y type=302
```

The service uses the first `v=afwd1` record it finds at `_afwd.<host>`, at `<host>` itself (following CNAMEs), and then at `_afwd.<target>` for the target of a CNAME at `<host>`. A name with a CNAME cannot have its own TXT record, so `go.example.com CNAME fwd.afwd.nl` is configured at `_afwd.go.example.com`. If the `_afwd.` lookup gets SERVFAIL or REFUSED but the record on the name is found, that record is used for redirects, but not for certificates. Two `v=afwd1` records at the same name make the record invalid.

The full behaviour is specified in [`spec/afwd-spec.txt`](spec/afwd-spec.txt), an RFC-style specification for anyone who builds a compatible service. The help site lays it out in pages and serves it at `/spec` (HTML) and `/spec.txt` (plain text). The spec tests in `crates/afwd-site/src/spec.rs` check the layout and that every section reference and citation resolves.

With `preserve=y` the request path and query string are added to the destination, so `/blog/post?x=1` goes to `https://example.net/blog/post?x=1`. A query in the destination is kept and comes first: with `dest=https://example.net/?ref=a`, the same request goes to `https://example.net/blog/post?ref=a&x=1`. Without `preserve`, every request goes to the destination as written. Permanent redirects (301, 308) carry `Cache-Control: max-age=3600`, so browsers pick up changes to the record within an hour.

Set `AFWD_PUBLIC_IPV4` and `AFWD_PUBLIC_IPV6` to comma-separated public addresses. The help page uses these values in its DNS examples. Set `AFWD_HELP_DOMAIN` to change the domain that shows the help page; it defaults to `afwd.nl`.

The help domain serves a landing page at `/` and the full documentation at `/docs`. The landing page shows live totals from `GET /api/summary` (requests and domains over the last 90 days, excluding the help domain) and has a record builder and a domain checker. The checker calls `GET https://<help domain>/api/check/example.com`, which reports the domain's A/AAAA addresses (and whether they match `AFWD_PUBLIC_IPV4`/`AFWD_PUBLIC_IPV6` or the target host's current addresses), its CNAME target, its `v=afwd1` record and the name it was found at, any error in that record, and the resulting redirect. When a domain points at the service without a usable record, the 404 page shows the reason and links to the checker.

The HTML pages are askama templates in `templates/`. They are compiled into the binary.

The help domain also serves `/.well-known/security.txt`, with Trilobit's published contact address (`info@trilobit.nl`) and a rolling one-year expiry.

Run the complete service with Docker Compose. Copy `deploy/.env.example` to `deploy/.env` and fill in the public addresses, then build and start it:

```powershell
docker compose -f deploy/compose.yml up --build -d
```

On a server, use the images that CI publishes (`ghcr.io/thijsk/afwd-proxy`, `-edge` and `-site`) instead of building:

```powershell
docker compose -f deploy/compose.yml pull
docker compose -f deploy/compose.yml up -d
```

The volumes keep the names of the earlier single-container setup (`afwd-data`, `afwd-config`, `afwd-stats`), and Caddy uses the same certificate path, so certificates and statistics carry over. View HTTP access logs with `docker compose -f deploy/compose.yml logs -f proxy`.

To test locally without HTTPS, set `AFWD_HTTP_PORT` (for example `8080`) and send requests with a Host header, such as `curl -H "Host: afwd.nl" http://127.0.0.1:8080/`.

## Usage statistics

The service counts requests for each domain that has an AFWD TXT record. It also counts visits to `/`, `/docs`, `/spec` and `/stats` on the help domain, but not `/domains`, the `/api/` endpoints, or security.txt. It counts hits by hour and status, paths, and referrer domains. It does not store IP addresses, user agents, or query strings. It counts at most 20 names per registrable domain each hour, so a wildcard record cannot give every made-up subdomain counters of its own. The statistics are kept for 90 days. The public `/domains` page lists the 100 domains with the most requests during that period, excluding the help domain.

The statistics are stored in the SQLite file `AFWD_STATS_DB` (default `/stats/afwd.db` in Docker). `edge` and `site` share the `afwd-stats` volume: `edge` counts forwarded requests, `site` counts help pages and reads the statistics.

To see the statistics for a domain, the owner opens `https://<help domain>/stats` and creates a token. Then the owner adds this TXT record:

```text
_afwd-stats.example.com. 3600 TXT "v=afwdstats1 h=<sha256 hex of token>"
```

The API is `GET https://<help domain>/api/stats/example.com` with the header `Authorization: Bearer <token>`. To rotate tokens, add more `h=` records. To remove access, delete the record.

## Local HTTPS testing

Add `127.0.0.1 afwd.nl` to your hosts file. Start the help site with `cargo run --bin afwd-site`, then run Caddy with `deploy/Caddyfile.local`. Run `caddy trust` once so your browser trusts Caddy's local certificate.

## Development

```powershell
cargo test
cargo run --bin afwd-edge   # forwarding service on 127.0.0.1:8080
cargo run --bin afwd-site   # help site on 127.0.0.1:8081
```

Set `AFWD_BIND` to change the address. `deploy/Caddyfile` routes a Caddy installed on the host to these two addresses.

CI also checks that every dependency uses a permissive license, with `cargo deny check licenses` and the allow list in `deny.toml`.

## License

Copyright © 2026 Trilobit.

afwd is licensed under the GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE). If you run a modified version as a network service, the AGPL requires you to offer its source code to the users of that service.

Trilobit may also offer afwd under other terms, including closed source. To keep that possible, contributions are accepted under the Contributor License Agreement in [CONTRIBUTING.md](CONTRIBUTING.md), and dependencies must use permissive licenses.
