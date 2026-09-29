# Validation — 2.2.0 protocol audit and readable results

Reviewed main 3736952 (including the simplified README and appreciation image). README and user content are preserved.

## Confirmed and repaired

- SA_INIT successful responses previously accepted unoffered proposal numbers, duplicate/unoffered transform types/IDs and malformed attributes. Validate the single offered proposal and four selected transforms; legal transform ordering and TV/TLV key-length encodings are covered by positive tests.
- UNSUPPORTED_CRITICAL_PAYLOAD notifications now require the offending payload type byte.
- DNS parsing previously returned an A record without checking missing authority/additional records or trailing bytes. Validate all declared record envelopes and the whole datagram, including negative answers; only Answer-section A records/CNAMEs supply target addresses.
- Reject malformed A record lengths, conflicting CNAME targets and simultaneous CNAME/A at the queried owner.
- Reject target strings with spaces/control characters/unsupported IPv6 before sending; normalize a trailing DNS root dot. Unmatched filters now fail before DNS reference requests and DH computation.
- Separate terminal input and output streams; avoid switching a C update stream from input to output without positioning. Stop immediately if EOF/error occurs while draining oversized menu input.

## Display changes

- All country/carrier labels use the same bold cyan color on a terminal.
- Green: both ports replied on the same IP; yellow: partial or unconfirmed; red: local probe error. Results explicitly leave actual calls to a phone test.
- Default output is one plain-language line per carrier. --details exposes technical diagnostics. Redirected output has no ANSI codes; NO_COLOR disables terminal colors.
- Positive/negative result presentation, PTY colors, NO_COLOR and details mode have regression coverage.

## Evidence

- Five added regression methods failed on the pre-fix code as expected.
- All 49 local tests pass with ASan/UBSan. Clang static analysis reports no warnings.
- Tests include positive protocol packets, malformed packets, loopback UDP, menu/PTY pipe interaction, country selection, launcher failures and binary hash checks.
- Zig 0.13.0 cross-builds static x86_64 and aarch64 Linux binaries; hashes are updated together.
- GitHub Actions runs the same tests on Linux, plus 64 MiB/no-swap Alpine/Debian/Ubuntu containers and a byte-identical source rebuild. Consult Actions for the exact release commit.

## Remaining limits

This is an unauthenticated IPv4 IKE return-path probe. It does not validate SIM authentication, IMS registration, voice calls, phone-to-VPS routing, IPv6/NAT64 or sustained UDP sessions. Timeout remains unconfirmed, not proof of blocking. PLMN-derived carrier domains remain candidates, not a certified live endpoint inventory.

DNS does not implement TCP fallback, /etc/hosts or search domains. CNAME resolution currently expects the final A record in the same Answer section; a CNAME-only answer may remain unresolved. No actual NAT VPS or phone call was tested in this audit.

Protocol references: https://www.rfc-editor.org/rfc/inline-errata/rfc7296.html and https://www.rfc-editor.org/rfc/inline-errata/rfc1035.html
