FROM rust:1-slim-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM caddy:2-alpine AS caddy

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install --no-install-recommends --yes ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

ENV AFWD_BIND=127.0.0.1:9000 \
	CADDY_DATA_DIR=/data \
	CADDY_CONFIG_DIR=/config \
	AFWD_STATS_DB=/stats/afwd.db \
	HOME=/data

EXPOSE 8080 8443

COPY --from=builder /app/target/release/afwd /usr/local/bin/afwd
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY deploy/Caddyfile.container /etc/caddy/Caddyfile
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir --parents /data /config /stats \
	&& chmod 0555 /usr/local/bin/entrypoint.sh \
	&& chown --recursive 65532:65532 /data /config /stats /etc/caddy /usr/local/bin/afwd /usr/local/bin/caddy /usr/local/bin/entrypoint.sh

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]