#!/bin/sh
# WiFi Calling v2: tiny static native probe, no package manager or root required.
set -eu
HASH_x86_64=814348c58cdd771a34af0b52ba31516c89040e55656720ca0081bf2d6ccbc0a7
HASH_aarch64=c37d4a163865e9680a81e472cd085583486dbfefad8a5e5d61454aa86db1959e
fail() { printf '%s\n' "$*" >&2; exit 1; }
if [ "${1:-}" = --help ]; then
    printf '%s\n' 'WiFi Calling 2.0.0 / 64 MB 低内存设计' \
        '用法: sh check.sh [--filter 英国] [--host 域名或IPv4] [--dns DNS地址] [--timeout 毫秒]' \
        '也支持 --list、--version；默认串行 IPv4 检测，完整扫描可能需要数分钟。' \
        'Linux x86_64 / aarch64；只需 curl 或 wget，以及 sha256sum 或 shasum。' \
        '不安装软件、不修改防火墙、不创建 swap；结果仅表示 IKE 返回路径证据。'
    exit 0
fi
if [ "${1:-}" = --version ]; then printf '%s\n' 2.0.0; exit 0; fi
[ "$(uname -s)" = Linux ] || fail '此入口用于 Linux VPS。其他系统可从 src/check.c 自行编译。'
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64; expected=$HASH_x86_64 ;;
    aarch64|arm64) arch=aarch64; expected=$HASH_aarch64 ;;
    *) fail '暂未提供该架构的预编译程序；请在开发机编译 src/check.c。' ;;
esac
if command -v sha256sum >/dev/null 2>&1; then hasher=sha256sum
elif command -v shasum >/dev/null 2>&1; then hasher=shasum
else fail '缺少 SHA-256 校验工具，已停止；需要 sha256sum（BusyBox 通常自带）或 shasum。'
fi
base=${WIFICALLING_BASE_URL:-https://raw.githubusercontent.com/imthnio/wificalling-jiance/main}
case "$base" in https://*) ;; *) fail '下载地址必须使用 HTTPS。' ;; esac
umask 077
scratch=$(mktemp -d "${WIFICALLING_TMPDIR:-${TMPDIR:-/tmp}}/wificalling.XXXXXX") || fail '无法创建临时目录。'
trap 'rm -rf "$scratch"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
file=$scratch/check
url=$base/bin/check-linux-$arch
printf '%s\n' '下载低内存检测程序（不安装 Python 或其他软件）...'
if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --proto-redir '=https' -fSL --connect-timeout 10 --max-time 60 "$url" -o "$file" || fail '下载失败；请检查 HTTPS/DNS，稍后重试。'
elif command -v wget >/dev/null 2>&1; then
    wget -T 30 -q -O "$file" "$url" || fail '下载失败；请检查 HTTPS/DNS/CA 证书，稍后重试。'
else fail '没有 curl 或 wget。请通过 SSH 上传 bin/ 下对应架构的程序运行。'
fi
if [ "$hasher" = sha256sum ]; then
    actual=$(sha256sum "$file") || fail 'SHA-256 计算失败。'
else actual=$(shasum -a 256 "$file") || fail 'SHA-256 计算失败。'
fi
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail '程序校验失败（下载损坏或版本不匹配）；已停止，请重新下载 check.sh。'
chmod 700 "$file" || fail '无法设置执行权限。'
status=0
"$file" "$@" || status=$?
if [ "$status" -eq 126 ]; then
    printf '%s\n' '不能执行：临时目录可能设置了 noexec。可设置 WIFICALLING_TMPDIR 为可写、可执行目录后重试。' >&2
fi
exit "$status"
