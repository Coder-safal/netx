# netx requirements

## 1. Purpose

Help Linux users identify DNS, connectivity, TLS, and HTTP failures using readable
reports and predictable command exits.

## 2. Release scope

The current 0.1.0 development build provides `dns`, `http`, `tls`, `diagnose`,
`check`, `tcp`, `ports`, `ping`, and `trace`, with shared text/JSON reports.
Later-roadmap command features were included at the user's request. Publishing,
remote CI verification, and external documentation review remain release tasks.

## 3. Platform

Target Ubuntu 22.04 and 24.04, initially on x86-64. Core checks must run without
root. Privileged checks introduced later must explain missing permissions.

## 4. Language and build

Use C++17 and CMake 3.20 or newer. Build out of tree. Provide CTest integration
and an install target. Keep third-party dependencies explicit.

## 5. Build tools

On Ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake python3 openssl
```

Git is needed for source control. Ninja is optional. CI builds with the platform
compiler and Make in both Debug and Release configurations.

## 6. Libraries

The implementation uses the C++ standard library, Linux libc `libresolv`, and
libcurl. The supported Ubuntu configuration uses libcurl's OpenSSL TLS backend:

```sh
sudo apt-get install libcurl4-openssl-dev iputils-ping traceroute
```

OpenSSL development headers are not required directly. The `openssl` executable
generates TLS test fixtures. `ping` and `traceroute` are optional runtime helpers:
missing ICMP falls back to TCP, missing traceroute is reported as SKIPPED. Tests
use loopback fixtures and need no internet. CPack's DEB generator uses
`dpkg-shlibdeps` to derive distribution-specific runtime library dependencies.

## 7. CLI and output

Follow CLI_SPEC.md. Share one result type between checks and between renderers.
Provide text and JSON reports. Reject invalid input clearly. Never report an
unimplemented check as successful.

## 8. Reliability

Bound all network steps with timeouts. Bound response bodies and redirects;
detect redirect loops. Validate certificates and hostnames. Preserve useful
errors while avoiding crashes on malformed responses.

## 9. Testing

Run offline unit and integration tests in Ubuntu CI. Network fixtures must cover
success, malformed responses, failure, and timeout. Compare actual checks with
standard diagnostic tools before the first network release.

## 10. Distribution

Use the MIT license. Create the GitHub repository, push the source, and enable
the included workflow. Tag each completed release. Attach a Linux executable to
the v0.1.0 GitHub Release. Publishing requires an available repository and an
authenticated account; local build success does not establish published status.

## 11. Version 0.1 acceptance criteria

- DNS queries A, AAAA, CNAME, MX, NS, and TXT with TTL and elapsed time; honors
  `--type` and `--server`; distinguishes NXDOMAIN, SERVFAIL, and timeout.
- HTTP reports status, redirect chain, and DNS/connect/TLS/first-byte/total
  timings; enforces redirect count, loop detection, body limit, and timeout.
- TLS sends SNI and reports certificate validity dates, remaining days,
  hostname match, and chain trust. Expired certificates fail; certificates
  expiring within 30 days warn. Invalid trust or hostname fails.
- Diagnose runs DNS, TCP, TLS, then HTTP as applicable; skips dependent steps
  after failure; includes an understandable conclusion and useful hints.
- All checks use a common result model and both text and JSON renderers.
- Exit codes 0, 1, 2, and 3 follow CLI_SPEC.md, and network operations time out.
- Offline tests cover each command, failure classification, and dependency skips.
- Manual comparisons against `dig`, `curl`, and `openssl s_client` are recorded.
- Ubuntu CI passes and a versioned Linux binary is ready for the v0.1.0 release.
