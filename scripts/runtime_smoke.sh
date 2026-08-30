#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: scripts/runtime_smoke.sh IMAGE}
smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/derpex-runtime-smoke.XXXXXX")
container="derpex-runtime-smoke-$$"
self_issuer_container="derpex-runtime-smoke-self-$$"
acme_container="derpex-runtime-smoke-acme-$$"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker rm --force "$self_issuer_container" >/dev/null 2>&1 || true
  docker rm --force "$acme_container" >/dev/null 2>&1 || true
  rm -rf "$smoke_root"
}

trap cleanup EXIT

mkdir -p "$smoke_root/active" "$smoke_root/replacement"

for directory in active replacement; do
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -keyout "$smoke_root/$directory/tls.key" \
    -out "$smoke_root/$directory/tls.crt" \
    -days 1 \
    -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost \
    >/dev/null 2>&1
done

# These are disposable test keys. Make the bind-mounted files readable by the
# fixed non-root UID in the runtime image without changing the image user.
chmod 0644 "$smoke_root/active/tls.key" "$smoke_root/replacement/tls.key"

container_id=$(
  docker run \
    --rm \
    --detach \
    --name "$container" \
    --publish 127.0.0.1::443 \
    --volume "$smoke_root/active:/certs:ro" \
    --env DERPEX_LISTEN_PORT=443 \
    --env DERPEX_IDENTITY_PATH=/tmp/derpex.key \
    --env DERPEX_TLS_CERTFILE=/certs/tls.crt \
    --env DERPEX_TLS_KEYFILE=/certs/tls.key \
    --env DERPEX_TLS_RELOAD_INTERVAL_MS=250 \
    "$image"
)

published=$(docker port "$container" 443/tcp)
port=${published##*:}

for _attempt in {1..40}; do
  if curl --fail --insecure --silent --show-error --max-time 2 \
    "https://127.0.0.1:$port/derp/probe" \
    --output /dev/null 2>/dev/null; then
    break
  fi

  sleep 0.25
done

curl --fail --insecure --silent --show-error --max-time 2 \
  "https://127.0.0.1:$port/derp/probe" \
  --output /dev/null

fingerprint() {
  openssl s_client \
    -connect "127.0.0.1:$port" \
    -servername localhost \
    -showcerts \
    </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256
}

initial_fingerprint=$(fingerprint)
cp "$smoke_root/replacement/tls.crt" "$smoke_root/active/tls.crt"
cp "$smoke_root/replacement/tls.key" "$smoke_root/active/tls.key"

rotated_fingerprint=$initial_fingerprint

for _attempt in {1..40}; do
  rotated_fingerprint=$(fingerprint)

  if [[ "$rotated_fingerprint" != "$initial_fingerprint" ]]; then
    break
  fi

  sleep 0.25
done

if [[ "$rotated_fingerprint" == "$initial_fingerprint" ]]; then
  echo "runtime did not serve the rotated TLS certificate" >&2
  docker logs "$container" >&2
  exit 1
fi

if [[ $(docker inspect --format '{{.Id}} {{.State.Running}}' "$container") != "$container_id true" ]]; then
  echo "runtime container restarted or stopped during certificate rotation" >&2
  docker logs "$container" >&2
  exit 1
fi

if ! docker logs "$container" 2>&1 | grep -q "DERP TLS certificate reloaded successfully"; then
  echo "runtime did not report a successful TLS certificate reload" >&2
  docker logs "$container" >&2
  exit 1
fi

echo "compiler-free runtime served TLS and hot-reloaded its certificate"

# An ACME certificate mode answers HTTP-01 over plaintext HTTP, so a
# configuration without a cleartext listener could never complete an order and
# has to stop the container rather than fail on the first renewal.
acme_status=0
acme_output=$(
  docker run \
    --rm \
    --env DERPEX_LISTEN_PORT=443 \
    --env DERPEX_IDENTITY_PATH=/tmp/derpex.key \
    --env DERPEX_CERT_MODE=letsencrypt \
    --env DERPEX_CERT_DIR=/tmp/derpex-certs \
    --env DERPEX_CERT_HOSTNAME=derp.example.com \
    "$image" 2>&1
) || acme_status=$?

if [[ "$acme_status" -eq 0 ]]; then
  echo "runtime started an ACME mode with no plaintext listener" >&2
  printf '%s\n' "$acme_output" >&2
  exit 1
fi

if ! grep -q "DERPEX_HTTP_PORT" <<<"$acme_output"; then
  echo "ACME refusal did not name DERPEX_HTTP_PORT" >&2
  printf '%s\n' "$acme_output" >&2
  exit 1
fi

echo "runtime refused an ACME certificate mode with nowhere to answer a challenge"

# With a plaintext listener the relay boots, binds TLS on a self-signed
# certificate while the first order is outstanding, and answers the HTTP-01
# path. The order itself cannot complete here — a real certificate authority
# cannot reach this container — so the ACME flow proper is gated by the fake
# authority in test/support/fake_acme.ex, which drives it over real sockets.
docker run \
  --rm \
  --detach \
  --name "$acme_container" \
  --publish 127.0.0.1::80 \
  --env DERPEX_LISTEN_PORT=443 \
  --env DERPEX_HTTP_PORT=80 \
  --env DERPEX_IDENTITY_PATH=/tmp/derpex.key \
  --env DERPEX_CERT_MODE=letsencrypt \
  --env DERPEX_CERT_DIR=/tmp/derpex-certs \
  --env DERPEX_CERT_HOSTNAME=derp.example.com \
  --env DERPEX_ACME_DIRECTORY_URL=http://127.0.0.1:1/directory \
  --env DERPEX_STUN=0 \
  "$image" >/dev/null

acme_published=$(docker port "$acme_container" 80/tcp)
acme_port=${acme_published##*:}
acme_up=0

for _attempt in {1..40}; do
  status=$(
    curl --silent --output /dev/null --write-out '%{http_code}' --max-time 2 \
      "http://127.0.0.1:$acme_port/.well-known/acme-challenge/absent" || true
  )

  if [[ "$status" == "404" ]]; then
    acme_up=1
    break
  fi

  sleep 0.25
done

if [[ "$acme_up" -ne 1 ]]; then
  echo "runtime did not answer the HTTP-01 challenge path" >&2
  docker logs "$acme_container" >&2
  exit 1
fi

echo "compiler-free runtime booted an ACME mode and answered its challenge path"

# The one certificate source DERPEX can supply on its own: a self-signed
# per-IP certificate, issued at boot and served to a client that sends no SNI.
docker run \
  --rm \
  --detach \
  --name "$self_issuer_container" \
  --publish 127.0.0.1::443 \
  --env DERPEX_LISTEN_PORT=443 \
  --env DERPEX_IDENTITY_PATH=/tmp/derpex.key \
  --env DERPEX_IP_CERT_ISSUER=self \
  --env DERPEX_CERT_DIR=/tmp/derpex-certs \
  --env DERPEX_CERT_HOSTNAME=127.0.0.1 \
  --env DERPEX_STUN=0 \
  "$image" >/dev/null

self_issuer_published=$(docker port "$self_issuer_container" 443/tcp)
self_issuer_port=${self_issuer_published##*:}
self_issuer_up=0

for _attempt in {1..40}; do
  if curl --fail --insecure --silent --show-error --max-time 2 \
    "https://127.0.0.1:$self_issuer_port/derp/probe" \
    --output /dev/null 2>/dev/null; then
    self_issuer_up=1
    break
  fi

  sleep 0.25
done

if [[ "$self_issuer_up" -ne 1 ]]; then
  echo "runtime did not serve TLS with DERPEX_IP_CERT_ISSUER=self" >&2
  docker logs "$self_issuer_container" >&2
  exit 1
fi

# The listener binds a self-signed placeholder and serves TLS while the real
# per-IP certificate is still being issued, so TLS answering does not mean the
# certificate has been cached yet. Poll for the cache the same way TLS was
# polled for.
self_issuer_cached=0

for _attempt in {1..40}; do
  if docker exec "$self_issuer_container" test -f /tmp/derpex-certs/127.0.0.1.crt; then
    self_issuer_cached=1
    break
  fi

  sleep 0.25
done

if [[ "$self_issuer_cached" -ne 1 ]]; then
  echo "self issuer did not cache its certificate within ten seconds" >&2
  docker logs "$self_issuer_container" >&2
  exit 1
fi

echo "compiler-free runtime served a self-issued IP certificate"
