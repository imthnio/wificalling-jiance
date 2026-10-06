#!/bin/sh
# 编译（带 ASan/UBSan）并运行本地回环测试。
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' 0
${CC:-cc} -std=c99 -Wall -Wextra -Werror -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    src/check.c -o "$out/check"
python3 -I tests/test_check.py "$out/check"
