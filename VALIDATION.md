# Validation — 2026-09-28

Base: `74873a95a6c561daad847b631296bd0b8b504e2b`.

- macOS ARM64: C99 builds with `-Wall -Wextra -Werror` passed.
- 19 protocol/CLI tests passed, including loopback UDP peers and an unrelated-source rejection test.
- 12 launcher/distribution tests passed, including curl, wget-only, SHA mismatch, cleanup and child exit status.
- The 19 protocol tests also passed with AddressSanitizer and UndefinedBehaviorSanitizer.
- DH group-14 prime matches the RFC 3526 published value; modular exponentiation matches independent Python `pow()` across five inputs.
- Cross-built with Zig 0.13.0: static stripped Linux x86_64 and aarch64 ELF files, with embedded expected SHA-256 values in `check.sh`.
- macOS local diagnostic (`--host 127.0.0.1 --dns 127.0.0.1 --timeout 50`): exit 0, child peak RSS 1,654,784 bytes (about 1.58 MiB). This is NOT a Linux/container memory measurement.
- 64 MiB/no-swap Linux container tests are provided in `scripts/test-64mb.sh` and CI, but were not run on the local macOS host (no Docker runtime).
- Real target NAT VPS, actual carrier reachability, SIM registration and calls: not tested.

No runtime credentials or user VPS data are included. Test addresses are loopback or documentation ranges. The distribution contains only source, tests, build/CI scripts, documentation, third-party notices and the two generated Linux binaries.
