# Builds the three afwd images. Pick one with --target:
#
#   proxy  Caddy: HTTPS certificates and routing for every host
#   edge   the forwarding service, for every host except the help domain
#   site   the help site (afwd.nl)
#
# deploy/compose.yml builds and runs all three.

FROM rust:1-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY templates ./templates
COPY spec ./spec

RUN cargo build --release --locked --bins

FROM caddy:2-alpine AS caddy

FROM debian:bookworm-slim AS base

RUN apt-get update \
	&& apt-get install --no-install-recommends --yes ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

FROM base AS proxy

# Caddy keeps certificates in $XDG_DATA_HOME/caddy. This is the path the earlier
# single-container image used (it set HOME=/data), so existing certificates carry over.
ENV XDG_DATA_HOME=/data/.local/share \
	XDG_CONFIG_HOME=/config \
	HOME=/data

COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY deploy/Caddyfile.container /etc/caddy/Caddyfile

RUN mkdir --parents /data /config \
	&& chown --recursive 65532:65532 /data /config

USER 65532:65532
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

FROM base AS app

ENV AFWD_BIND=0.0.0.0:9000 \
	AFWD_STATS_DB=/stats/afwd.db

RUN mkdir --parents /stats \
	&& chown 65532:65532 /stats

USER 65532:65532
EXPOSE 9000

FROM app AS site

COPY --from=builder /app/target/release/afwd-site /usr/local/bin/afwd-site
ENTRYPOINT ["/usr/local/bin/afwd-site"]

FROM app AS edge

COPY --from=builder /app/target/release/afwd-edge /usr/local/bin/afwd-edge
ENTRYPOINT ["/usr/local/bin/afwd-edge"]
