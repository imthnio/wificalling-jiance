#!/bin/sh
# Developer/CI check: Docker is required HERE, never on the target VPS.
set -eu
cd "$(dirname "$0")/.."
for image in alpine:3.22 debian:13-slim ubuntu:24.04; do
    printf '\nTesting %s with 64 MiB RAM, no swap, no capabilities, non-root\n' "$image"
    name="wificalling-memory-$$"
    trap 'docker rm -f "$name" >/dev/null 2>&1 || true' 0 INT TERM
    docker run --name "$name" --memory=64m --memory-swap=64m --pids-limit=16 \
        --cap-drop=ALL --security-opt=no-new-privileges --read-only --network=none \
        --user=65534:65534 -v "$PWD/bin:/probe:ro" "$image" \
        /probe/check-linux-x86_64 --host 127.0.0.1 --dns 127.0.0.1 --timeout 50
    [ "$(docker inspect -f '{{.State.OOMKilled}}' "$name")" = false ]
    [ "$(docker inspect -f '{{.State.ExitCode}}' "$name")" = 0 ]
    docker rm "$name" >/dev/null
    trap - 0 INT TERM
 done
