# Validation — 2.1.0 country menu

- 39 local macOS ARM64 regression tests passed (27 protocol/CLI/menu tests and 12 launcher tests).
- Menu tests cover number/name selection, invalid/empty/oversized input, cancellation, EOF, explicit all-country mode, and conflicting arguments.
- A pseudo-terminal test verifies country input still works when standard input is a pipe. No controlling terminal without a selector returns a clear error before network probes.
- Country integration tests use loopback DNS only: USA/Canada select exactly 3 carriers; UK selects 4; --all selects 42.
- USA retains T-Mobile/AT&T/Verizon. Canada adds Rogers 302-720, Bell 302-610, TELUS 302-220, checked against https://cnac.ca/data/MNC_Codes.htm . These are PLMN-derived candidates, not verified service endpoints.
- Zig 0.13.0 builds static Linux x86_64 and aarch64 binaries; SHA256SUMS and launcher hashes are regenerated together.
- GitHub Actions tests protocol/launcher regressions, ASan/UBSan, hashes, 64 MiB/no-swap Linux containers and reproducible builds. Check the run for the exact current commit.
- The earlier 2.0.0 baseline passed https://github.com/imthnio/wificalling-jiance/actions/runs/36469713502 . That older run is not evidence for this new revision.
- Actual NAT VPS, SIM registration, real calls and IPv6 remain untested.
