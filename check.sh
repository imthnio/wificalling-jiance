#!/bin/sh
# WiFi Calling 网络探测启动器：优先下载预编译静态程序并校验 SHA-256；
# 没有预编译程序时，若本机有 C 编译器则下载源码现场编译。不需要 root，不安装任何软件。
set -eu
# 程序与 check.sh 在同一分支发布，SHA-256 校验保证二者匹配。
BASE_URL=${WIFICALLING_BASE_URL:-https://raw.githubusercontent.com/imthnio/wificalling-jiance/main}
HASH_x86_64=e0d4dab25018f42d5fbc93ccca803d0115ea9275ee65e7958f1be9397d31fda7
HASH_aarch64=3c733e1cd93d6e00d393d2144b54222d6f8359bb9dc366fd1c85ec10e9a55f04

fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail '此脚本用于 Linux VPS。'
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64; expected=$HASH_x86_64 ;;
    aarch64|arm64) arch=aarch64; expected=$HASH_aarch64 ;;
    *) arch=; expected= ;;
esac
case "$BASE_URL" in https://*) ;; *) fail '下载地址必须是 HTTPS。' ;; esac

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' -fsSL --connect-timeout 10 --max-time 60 "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -T 30 -q -O "$2" "$1"
    else
        fail '需要 curl 或 wget。'
    fi
}
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1"
    else return 1
    fi | { read -r h _; printf '%s' "$h"; }
}

umask 077
dir=$(mktemp -d "${WIFICALLING_TMPDIR:-${TMPDIR:-/tmp}}/wificalling.XXXXXX") || fail '无法创建临时目录。'
trap 'rm -rf "$dir"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
prog=$dir/check

if [ -n "$arch" ] && [ -n "$expected" ]; then
    echo '下载检测程序…'
    fetch "$BASE_URL/bin/check-linux-$arch" "$prog" || fail '下载失败，请检查网络后重试。'
    actual=$(sha256 "$prog") || fail '缺少 sha256sum 或 shasum，无法校验，已停止。'
    [ "$actual" = "$expected" ] || fail '程序校验失败（下载损坏或版本不匹配），已停止。'
else
    cc=$(command -v cc || command -v gcc || command -v clang || true)
    [ -n "$cc" ] || fail '没有该架构的预编译程序，本机也没有 C 编译器。'
    echo '下载源码并编译…'
    fetch "$BASE_URL/src/check.c" "$dir/check.c" && fetch "$BASE_URL/src/carriers.h" "$dir/carriers.h" ||
        fail '下载源码失败。'
    "$cc" -std=c99 -O2 -o "$prog" "$dir/check.c" || fail '编译失败。'
fi
chmod 700 "$prog"
status=0
"$prog" "$@" || status=$?
[ "$status" -ne 126 ] || echo '无法执行：临时目录可能是 noexec，可设置 WIFICALLING_TMPDIR 为可执行目录。' >&2
exit "$status"
