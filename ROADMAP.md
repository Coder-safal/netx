# netx: Roadmap

A step-by-step plan. Finish each version before starting the next. Small, finished releases beat a big unfinished one.

---

## Version 0.0: Setup (about 1 to 2 days)

Goal: an empty project that builds.

- [ ] Create the GitHub repository with a licence (MIT or Apache-2.0)
- [x] Add `README.md`, `REQUIREMENTS.md`, `CLI_SPEC.md`, `ARCHITECTURE.md`, `ROADMAP.md`
- [x] Install build tools and libraries (see `REQUIREMENTS.md` sections 5 and 6)
- [x] CMake builds a program that prints its version
- [x] Argument parser works for `--help` and `--version`
- [x] Add the first unit test and run it
- [x] Set up continuous integration on Ubuntu

Done when: `netx --version` works and the test suite runs.

Local setup verified on 2026-10-27: Debug and Release builds each pass all three
CTest tests, and the installed executable prints `netx 0.0.0`. The MIT license
and Ubuntu 22.04/24.04 CI workflow are included. CMake was downloaded into
`/tmp/netx-build-tools` for local verification; use the README installation steps
for a permanent toolchain. Version 0.0 has no third-party runtime libraries.

Publishing remains pending: this workspace has no usable Git metadata or GitHub
CLI. The GitHub repository, first remote CI run, and release tag have not been
created. These publishing tasks remain open. At the user's request, the local
updates implement the remaining local commands ahead of remote release publication.

---

## Version 0.1: Core checks (first public release)

Goal: the four commands recommended for the first release.

### `netx dns`
Current local development build: all nine commands are implemented, including
the later TCP/ports/ping/trace and polish features requested by the user.
See `docs/VALIDATION.md` for verified checks and remaining release gates.

- [x] Query A, AAAA, CNAME, MX, NS, TXT
- [x] Show TTL and lookup time
- [x] `--type` and `--server` options
- [x] Clear errors for NXDOMAIN, SERVFAIL, timeout

### `netx http`
- [x] Status code, redirect chain, redirect limit
- [x] Timing: DNS, connect, TLS, first byte, total
- [x] Body size limit and redirect loop detection

### `netx tls`
- [x] Handshake with SNI
- [x] Certificate dates, days left, host name match, trust chain
- [x] WARN and FAIL rules for expiry

### `netx diagnose`
- [x] DNS, then TCP, then TLS, then HTTP
- [x] SKIPPED logic for dependent steps
- [x] Plain-English conclusion and hints

### Shared
- [x] One result type used by every check
- [x] Text report and `--json` report
- [x] Exit codes 0, 1, 2, 3
- [x] Timeouts on every network step
- [x] Tests that do not need the internet
- [x] Manual comparison against `dig`, `curl`, `openssl s_client`

Done when: every item in `REQUIREMENTS.md` section 11 is true. Tag `v0.1.0` and attach a Linux binary to a GitHub Release.

---

## Version 0.2: Ports and TCP

Goal: server-side diagnosis.

- [x] `netx tcp` with `--ports`, IPv4 and IPv6 tested separately
- [x] `netx ports`: listening TCP and UDP ports from `/proc/net`
- [x] Program names where permitted, "unknown (permission denied)" where not
- [x] `--established` and `--port` filters
- [x] `netx check` short summary
- [x] Deployment-check mode: one command to confirm DNS, TCP, TLS and HTTP after configuring nginx

Done when: you can run `netx ports` and `netx diagnose` on a fresh VPS and understand what is wrong from the output alone.

---

## Version 0.3: Ping and route

Goal: reachability and path.

- [x] `netx ping` with ICMP when allowed, TCP fallback with a clear message
- [x] Latency, packet loss, jitter
- [x] `netx trace` where permissions and network allow
- [x] Clear SKIPPED messages when permission is missing

Done when: ping and trace work for a normal user or explain exactly why they cannot.

---

## Version 0.4: Polish

- [x] DNS comparison across several resolvers (`--compare`)
- [x] `--chain` for the full certificate chain
- [x] SOA, CAA and PTR records
- [x] Better hints for common failures
- [x] Man page and bash completion
- [x] JSON schema documented and frozen as schema 1

---

## Version 1.0: Stable release

- [x] All commands in `CLI_SPEC.md` working or clearly marked unsupported
- [x] Stable JSON schema
- [ ] Tests passing on Ubuntu 22.04 and 24.04
- [x] Memory checker and sanitizer runs clean
- [x] `.deb` package built
- [ ] Documentation reviewed by someone who did not write it

---

## After 1.0 (ideas)

- Ubuntu PPA on Launchpad so users can run `apt install netx`
- Node.js native addon exposing the checks to JavaScript
- Watch mode: repeat `diagnose` and alert by email or Telegram when something changes
- ARM64 builds
- Unicode (internationalised) domain support

---

## Work habits that help

1. Write the CLI output you want first (`CLI_SPEC.md`), then build toward it
2. Get one command fully working before starting the next
3. Compare every result with the standard tool (`dig`, `curl`, `ss`)
4. Keep each function small and each module free of printing
5. Tag a release after each version, even if small
