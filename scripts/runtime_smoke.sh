#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: scripts/runtime_smoke.sh IMAGE}
smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/derpex-runtime-smoke.XXXXXX")
container="derpex-runtime-smoke-$$"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
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
