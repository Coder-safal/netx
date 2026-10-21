# netx CLI specification

## Syntax

```text
netx [--help | --version]
netx dns HOST [--type TYPE] [--server IPV4[:PORT] | --compare IP,IP]
netx http URL [--max-redirects N] [--max-body BYTES] [--ca-file PATH]
netx tls HOST[:PORT] [--chain] [--ca-file PATH]
netx diagnose HOST_OR_URL [--deployment] [--chain] [--ca-file PATH]
netx check HOST_OR_URL [--deployment] [--chain] [--ca-file PATH]
netx tcp HOST [--ports PORT,PORT] [-4 | -6]
netx ports [--established] [--port PORT] [-4 | -6]
netx ping HOST [--count N] [--port PORT] [-4 | -6]
netx trace HOST [--max-hops N] [-4 | -6]
```

Every command accepts `--json` and `--help`. Network commands accept
`--timeout SECONDS`; `ports` does not. Except DNS, commands accept `-4` / `--ipv4`
and `-6` / `--ipv6`. Options can precede or follow the target. Unknown, repeated,
missing, conflicting, and out-of-range options return 2 with a help hint on
stderr. Top-level `-h` and `-V` alias help and version. No arguments prints help.

Bare hosts use HTTPS port 443 unless an explicit port is supplied. HTTP URLs use
port 80. IPv6 targets must be bracketed outside `dns`, e.g. `[::1]:8443`.
Only HTTP(S) schemes are accepted. URL credentials are rejected. HTTP(S) connects
directly, ignoring proxy environment variables. Private CAs can be supplied with
`--ca-file`; certificate validation is always enabled.

## DNS

Types: A (default), AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR. PTR accepts IPv4,
IPv6, or an already-reversed DNS name. Default resolver: system configuration.
`--server` accepts an IPv4 address, optionally followed by a port. `--compare`
queries each of up to 32 comma-separated resolvers and reports them separately.
No consensus or DNSSEC validation is claimed. Results include record data, TTL,
and elapsed time. NXDOMAIN, SERVFAIL, empty answers, malformed data, timeout,
and unavailable resolvers have explicit errors.

The timeout defaults to 2 seconds per resolver attempt; multiple system resolvers
and DNS TCP fallback can extend overall runtime. Names use ASCII DNS labels;
internationalised domains must be supplied in punycode form.

## HTTP and TLS

HTTP reports status, redirect chain, response bytes, remote address, and DNS,
connect, TLS, first-byte and total timings. HTTP status >=400 fails. Redirects
301/302/303/307/308 follow relative or absolute HTTP(S) locations. Repeated URLs,
more than 10 redirects by default, and bodies over 1 MiB across the chain fail.
`--max-redirects` accepts 0..50; `--max-body` accepts 1..104857600 bytes.
The timeout defaults to 5 seconds for the complete HTTP chain. Phase timings
refer to the final attempted hop; total spans the entire chain. Headers are
limited to 64 KiB across the chain. Response bodies are discarded, not printed.

TLS performs a handshake with SNI for DNS hostnames, verifies hostname and trust,
and reports the leaf subject, issuer, start/expiry dates, and days remaining.
Invalid trust/hostname, expired, or not-yet-valid certificates fail. Expiry within
30 days warns. `--chain` prints the chain sent by the server, which may omit the
root. Certificate dates unavailable from the libcurl backend produce WARN.

## Diagnose and check

Order: DNS, TCP, TLS, HTTP, conclusion. A literal IP bypasses DNS with an
explanation. DNS accepts either A or AAAA unless a family is forced. TCP passes
if either available family connects and includes both family outcomes. Failed
prerequisites cause dependent checks to be SKIPPED. Plain HTTP skips TLS as
inapplicable. `check` runs the same checks with a short text summary. `--deployment`
explicitly selects this same deployment-check behavior. Both also accept the HTTP
redirect/body limits. Each step has its own timeout; there is no overall deadline.

## TCP and local sockets

TCP checks IPv4 and IPv6 separately by default. Missing family records are
SKIPPED; connection errors fail. `--ports` accepts up to 32 comma-separated
ports (1..65535); default is the target URL's port. Timeout applies per connection.

Ports reads Linux `/proc/net/tcp`, `tcp6`, `udp`, and `udp6`: listening TCP and
bound/unconnected UDP sockets by default, established TCP with `--established`.
`--port` filters the local port. Socket inode owners are mapped through readable
`/proc/PID/fd` entries. Unavailable names show `unknown`, or `unknown (permission
denied)` if process inspection was denied. No root requirement is imposed.

## Ping and trace

Ping uses the `ping` helper with 1..20 packets (`--count`, default 4), reporting
latency, loss, and jitter (standard deviation). Missing/forbidden ICMP switches
to TCP probes at the target port or `--port`; successful fallback warns because
it measures TCP connection time rather than ICMP RTT. ICMP loss fails if no
replies arrive; partial loss warns. Probe timeout defaults to 5 seconds.

Trace uses the `traceroute` helper with one probe per hop and 1..64 maximum hops
(default 16). Missing helper/permission is SKIPPED, helper failure/deadline is
FAIL, incomplete or partially unanswered routes WARN. Full hop output is
included. Routers may filter probes. Each hop has its own timeout; a subprocess
deadline additionally bounds total execution. Helpers are executed with argument
arrays, never a shell command assembled from target input.

## Reports and exit codes

Every check uses PASS, WARN, FAIL, or SKIPPED. All commands support JSON schema 1
([schema](docs/json-schema-1.json)), containing the same results as text output.
Details are string-valued so units and record data remain explicit. JSON check
reports go to stdout, including failures. Invalid usage/internal execution errors
are plain stderr messages and are not schema reports. DNS text failures go to
stderr; other text check reports go to stdout.

Exit codes: 0 = all pass; 1 = any failure; 2 = invalid usage/internal error;
3 = warnings/skips without failure. The JSON `exit_code` matches the process exit.
