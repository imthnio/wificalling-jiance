#!/bin/sh
# 在开发机交叉编译静态二进制（需要 Zig），并把哈希写回 check.sh 和 SHA256SUMS。
set -eu
cd "$(dirname "$0")/.."
: "${ZIG:=zig}"
mkdir -p bin
for arch in x86_64 aarch64; do
    "$ZIG" cc -target "$arch-linux-musl" -static -std=c99 -Os -s -Wall -Wextra -Werror \
        -Wl,--build-id=none src/check.c -o "bin/check-linux-$arch"
done
if command -v sha256sum >/dev/null 2>&1; then sum() { sha256sum "$@"; }; else sum() { shasum -a 256 "$@"; }; fi
sum bin/check-linux-x86_64 bin/check-linux-aarch64 > SHA256SUMS
for arch in x86_64 aarch64; do
    h=$(sum "bin/check-linux-$arch" | cut -d' ' -f1)
    sed -i.bak "s/^HASH_$arch=.*/HASH_$arch=$h/" check.sh && rm -f check.sh.bak
done
cat SHA256SUMS
