#!/bin/sh
set -eu

/usr/local/bin/afwd &
afwd_pid=$!

/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &
caddy_pid=$!

cleanup() {
    kill "$afwd_pid" "$caddy_pid" 2>/dev/null || true
    wait "$afwd_pid" "$caddy_pid" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

while kill -0 "$afwd_pid" 2>/dev/null && kill -0 "$caddy_pid" 2>/dev/null; do
    sleep 1
done

exit 1
