#!/bin/sh
# Generate a self-signed certificate on first run, then start nginx.
set -e
CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ]; then
  echo "[sentinel] generating self-signed TLS certificate…"
  command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl
  openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout "$CERT_DIR/server.key" \
    -out    "$CERT_DIR/server.crt" \
    -subj   "/CN=sentinel.local" >/dev/null 2>&1
  echo "[sentinel] certificate created."
fi

exec nginx -g 'daemon off;'
