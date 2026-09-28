#!/bin/sh
# Build on a development machine, never on a 64 MB target VPS.
set -eu
cd "$(dirname "$0")/.."
: "${ZIG:=zig}"
[ "$("$ZIG" version)" = 0.13.0 ] || { echo 'Requires Zig 0.13.0' >&2; exit 1; }
mkdir -p bin
for arch in x86_64 aarch64; do
  "$ZIG" cc -target "$arch-linux-musl" -static -std=c99 -Os -s \
    -Wall -Wextra -Werror -Wl,--build-id=none src/check.c -o "bin/check-linux-$arch"
done
python3 scripts/update_hashes.py
