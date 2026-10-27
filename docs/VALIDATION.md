# Local validation — 2026-10-27

Environment: Ubuntu 24.04 x86-64, GCC 13.3, libcurl 8.5.0. Remote CI has not
been run; Ubuntu 22.04 is configured in the workflow but not verified locally.

## Automated checks

Five CTest entries: CLI unit tests, DNS packet unit tests, executable help/version
smoke tests, and an offline integration suite containing nine test groups.
Release, Debug, and AddressSanitizer + UndefinedBehaviorSanitizer configurations
are exercised. Fixtures require loopback socket access, but no internet access.

Integration coverage includes all nine CLI commands, invalid arguments, all nine
DNS record types, custom resolver/compare, IPv4/IPv6 PTR, NXDOMAIN, SERVFAIL,
missing records, DNS timeout, HTTP status errors, redirects/loops/limits, body
limits, HTTP timeout, TCP open/refused IPv4 and IPv6 sockets, local port filters
and established sockets, trusted/untrusted/hostname-mismatched/expired/soon-expiring
certificates, chain output, diagnose dependency skips, short check output, ICMP
statistics, TCP fallback, missing trace helper, and incomplete traces.

## Manual comparisons

- `netx dns safal.me` and `dig safal.me A +noall +answer` returned `76.76.21.21`.
  TTL changes between calls are expected because resolver caches count down.
- `netx http https://safal.me` and direct `curl` both returned HTTP 200. Both
  exposed DNS/connect/TLS/total timing; timings naturally vary between calls.
- `netx tls safal.me` and `openssl s_client` both verified the hostname and chain.
  The leaf certificate was valid from September 4 to December 3, 2026, issued
  by Let's Encrypt YR2. No private keys or session data are stored in this report.
- `netx diagnose safal.me` passed all four applicable checks. Its TCP details
  showed working IPv4 and missing IPv6 address records.
- Real ICMP ping and traceroute to 127.0.0.1 succeeded; controlled helper fixtures
  separately exercise permission/missing-helper handling and TCP fallback.

A Debian package was built with CPack and inspected using dpkg-deb. Dependencies
are calculated from linked libraries, so this Ubuntu 24.04 binary is not a
portable binary for Ubuntu 22.04; build a package on each supported distribution.
The package has not been installed system-wide or published.

## Remaining release work

The workspace lacks usable Git metadata and a GitHub remote/account setup.
Create/push the repository, run the Ubuntu CI matrix, create release tags, and
attach binaries before calling this a published release. Fresh VPS/nginx manual
validation and an independent documentation review also remain outstanding.
No external review, remote CI pass, or release publication is claimed.
