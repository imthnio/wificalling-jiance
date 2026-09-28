# Validation — 2026-09-29

Reviewed current main: `44863e3`; implementation reused from `99630fd` and audited further.

- 34 tests pass on macOS ARM64: 22 protocol/CLI and 12 launcher/distribution tests.
- All 34 tests also pass with AddressSanitizer and UndefinedBehaviorSanitizer.
- Clang static analysis and C99 compilation with -Wall -Wextra -Werror pass.
- New notification-only and oversized UDP regressions were run against the old native implementation and failed as expected (false-positive acceptance); the repaired implementation rejects them.
- Normal SA_INIT additionally requires a nonzero responder SPI, one group-14 KE payload of the correct length, and nonduplicated SA/KE/Nonce payloads.
- Both IKE and DNS receive paths reject MSG_TRUNC rather than inspecting a truncated prefix.
- Built with Zig 0.13.0: static stripped Linux x86_64 (60,008 bytes) and aarch64 (67,536 bytes), SHA-256 checked against manifest and launcher.
- GitHub Actions run 36469202413 passed on commit 589535a77079f6c8709251582b276972f5872ee1: regressions, ASan/UBSan, hashes, Alpine 3.22 / Debian 13 / Ubuntu 24.04 under 64 MiB/no swap, and byte-identical source rebuild. This is container evidence, not an actual NAT VPS test.
- Actual NAT VPS, carrier/SIM registration, IPv6, and calls were NOT tested.
- run-local.sh checks the bundled SHA256SUMS and runs the matching Linux binary. The README command uses main; the launcher pins its binaries to a fixed, verified commit.

Only source, tests, build/CI scripts, documentation, notices and generated binaries are distributed. No credentials or VPS data.

CI evidence: https://github.com/imthnio/wificalling-jiance/actions/runs/36469202413
