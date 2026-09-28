#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
: "${CC:=cc}"
"$CC" -std=c99 -O2 -Wall -Wextra -Werror ${CFLAGS:-} src/check.c -o build/check
"$CC" -std=c99 -O2 -Wall -Wextra -Werror ${CFLAGS:-} tests/harness.c -o build/harness
sh -n check.sh
sh -n scripts/build.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
