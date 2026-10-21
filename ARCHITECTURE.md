# Architecture

C++17, CMake, Linux libc resolver, and libcurl. `CMakeLists.txt` supplies the
version via generated `netx/version.hpp`. No network command invokes a shell.

- `main.cpp` adapts process arguments and standard streams.
- `cli.cpp` validates command-specific arguments, runs checks, and coordinates
  dependency skips for diagnose/check.
- `dns.cpp` constructs DNS queries with libc, sends them with bounded resolver
  retries, and decodes bounded records, including compressed names. Explicit DNS
  errors are preserved; PTR reverses address literals. A resolver function can
  be injected into CLI tests.
- `web.cpp` uses libcurl for asynchronous/bounded resolution, HTTP redirect/body
  handling, verified TLS handshakes, and per-family TCP connections. TLS uses
  connect-only mode, so no HTTP request is needed for certificate inspection.
- `system.cpp` reads Linux socket tables and owner inodes, and runs bounded ping
  and traceroute helper processes with captured output and process-group cleanup.
- `checks.hpp` defines options and the shared Result (status, summary, duration,
  string-valued details, hints).
- `report.cpp` renders text or schema-1 JSON and calculates exit codes.

Check modules do not print. Network resources use libcurl RAII or resolver guards;
helper execution captures output through a bounded pipe and kills/reaps timed-out
processes. Each check/probe has a finite timeout; diagnosis and multi-port checks
have multiple separately bounded steps rather than one global command deadline.

Offline C++ unit tests cover argument parsing, output, and malformed DNS packets.
The Python integration fixture hosts local DNS/HTTP/TLS services, generates test
certificates with openssl, and exercises real sockets plus controlled helper
programs. Tests need loopback access but no internet. Release and Debug tests run
on Ubuntu CI; passing local tests does not imply the remote CI has run.

Schema 1 is defined in `docs/json-schema-1.json`. New details can be added without
changing the schema; incompatible envelope/status changes require a new version.
CPack provides a Debian package. Install rules include the executable, man page,
and bash completion. GitHub publication remains a separate release task.
