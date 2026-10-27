# netx

C++17 network diagnostics for Linux. The current development version is **0.1.0**.
All nine commands below are implemented. Release publishing and cross-Ubuntu
verification remain pending; see [ROADMAP.md](ROADMAP.md).

## Build and test

On Ubuntu:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake libcurl4-openssl-dev python3 openssl iputils-ping traceroute
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Tests use loopback DNS, HTTP, and TLS servers and do not need internet access.
The test environment must permit local socket creation. Production builds can
use `-DBUILD_TESTING=OFF` to omit Python and test fixtures.

## Commands you can run

```sh
./build/netx --help
./build/netx --version
./build/netx dns safal.me
./build/netx dns safal.me --type MX
./build/netx dns safal.me --type TXT --server 1.1.1.1
./build/netx dns safal.me --compare 1.1.1.1,8.8.8.8
./build/netx dns 1.1.1.1 --type PTR
./build/netx http https://safal.me
./build/netx tls safal.me --chain
./build/netx diagnose safal.me
./build/netx check safal.me
./build/netx tcp safal.me --ports 80,443
./build/netx tcp safal.me --ports 443 -4
./build/netx ports
./build/netx ports --port 443
./build/netx ports --established
./build/netx ping safal.me --count 4
./build/netx trace safal.me --max-hops 16 --timeout 1
./build/netx diagnose safal.me --json
```

The default scheme for a bare hostname is HTTPS. Use `http://HOST:PORT` to check
plaintext HTTP. Bracket IPv6 targets, for example `tcp '[::1]' --ports 443 -6`.
Network failures and missing DNS record types are reported with reasons, not
as usage errors. IPv4 and IPv6 can have different outcomes.

Each command accepts `--json`. Most network commands accept `--timeout 1..30`;
DNS defaults to 2 seconds per resolver attempt, others to 5 seconds per network
step. Ping and trace apply the timeout to each probe. A diagnosis can therefore
last longer than one timeout interval. HTTP's timeout covers the whole redirect
chain. DNS resolvers must be IPv4 addresses, optionally `IP:PORT`.

Exit codes: **0** pass, **1** check failed, **2** invalid usage/internal error,
**3** warning or skipped check. Check `echo $?` immediately after a command.
Plain HTTP diagnosis reports TLS as SKIPPED and returns 3. Missing IPv6 records
are shown separately by `tcp`; diagnosis passes TCP when either family connects.
Ping uses the system `ping` helper, falling back to TCP when ICMP is unavailable.
Trace uses `traceroute` and reports SKIPPED when it is missing or forbidden.

TLS always verifies hostname and trust. Use `--ca-file PATH` for a private CA;
there is no insecure verification bypass. Certificates expiring within 30 days
warn; invalid/expired certificates fail. HTTP(S) checks connect directly and
ignore proxy environment variables, so they measure the target itself.

## Install or update

```sh
cmake --install build --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
netx diagnose safal.me
```

Add the PATH export to `~/.bashrc` to keep it in future terminals. Rebuild and
run the install command again after source changes to update your installed copy.
Installation includes a man page and bash completion under the chosen prefix.
To load the completion in the current shell:

```sh
source completions/netx.bash
```

Build a Debian package (requires Debian packaging tools):

```sh
cd build
cpack -G DEB
```

## Project documents

- [CLI behavior and options](CLI_SPEC.md)
- [Requirements](REQUIREMENTS.md)
- [Architecture](ARCHITECTURE.md)
- [JSON schema 1](docs/json-schema-1.json)
- [Roadmap and remaining release work](ROADMAP.md)

Licensed under the [MIT License](LICENSE).
