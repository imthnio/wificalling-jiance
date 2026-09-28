# Validation — 2026-09-29

Reviewed current main: `44863e3`; implementation reused from `99630fd` and audited further.

- 34 tests pass on macOS ARM64: 22 protocol/CLI and 12 launcher/distribution tests.
- All 34 tests also pass with AddressSanitizer and UndefinedBehaviorSanitizer.
- Clang static analysis and C99 compilation with -Wall -Wextra -Werror pass.
- New notification-only and oversized UDP regressions were run against the old native implementation and failed as expected (false-positive acceptance); the repaired implementation rejects them.
- Normal SA_INIT additionally requires a nonzero responder SPI, one group-14 KE payload of the correct length, and nonduplicated SA/KE/Nonce payloads.
- Both IKE and DNS receive paths reject MSG_TRUNC rather than inspecting a truncated prefix.
- Built with Zig 0.13.0: static stripped Linux x86_64 (60,008 bytes) and aarch64 (67,536 bytes), SHA-256 checked against manifest and launcher.
- No Docker runtime here: this revision has NOT been executed in the 64 MiB Linux container matrix. The included workflow and test script are available, but their existence is not a pass.
- Actual NAT VPS, carrier/SIM registration, IPv6, and calls were NOT tested.
- run-local.sh checks the bundled SHA256SUMS and runs the matching Linux binary. The repair is on fix/protocol-audit; GitHub main remains unchanged. The README command downloads the repair branch launcher, which pins its binaries to a fixed commit.

Only source, tests, build/CI scripts, documentation, notices and generated binaries are distributed. No credentials or VPS data.
