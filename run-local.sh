#!/bin/sh
# Run the verified binaries bundled with this archive, without downloading.
set -eu
cd "$(dirname "$0")"
[ "$(uname -s)" = Linux ] || { echo '请在 Linux VPS 上执行。' >&2; exit 1; }
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo '仅支持 x86_64 / aarch64。' >&2; exit 1 ;;
esac
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -c SHA256SUMS
else echo '缺少 sha256sum 或 shasum，停止执行。' >&2; exit 1
fi
chmod u+x "bin/check-linux-$arch"
exec "./bin/check-linux-$arch" "$@"
