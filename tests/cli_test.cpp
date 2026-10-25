#include "netx/cli.hpp"
#include "netx/version.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {
int failures = 0;

void expect(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void check_help(const std::vector<std::string_view>& arguments) {
    std::ostringstream output, errors;
    expect(netx::run_cli(arguments, output, errors) == 0, "help succeeds");
    expect(output.str().find("Usage: netx") != std::string::npos, "help includes usage");
    expect(errors.str().empty(), "help does not write errors");
}

void check_invalid(const std::vector<std::string_view>& arguments) {
    std::ostringstream output, errors;
    expect(netx::run_cli(arguments, output, errors) == 2, "invalid input returns 2");
    expect(output.str().empty(), "invalid input does not write stdout");
    expect(errors.str().find("--help") != std::string::npos, "error points to help");
}
}

int main() {
    check_help({});
    check_help({"--help"});
    check_help({"-h"});
    check_help({"dns", "--help"});
    for (const auto option : {"--version", "-V"}) {
        std::ostringstream output, errors;
        expect(netx::run_cli({option}, output, errors) == 0, "version succeeds");
        expect(output.str() == "netx " + std::string(netx::version) + "\n",
               "version output matches the configured project version");
        expect(errors.str().empty(), "version does not write errors");
    }
    check_invalid({"--unknown"});
    check_invalid({"dns"});
    check_invalid({"--version", "extra"});
    check_invalid({"--help", "--unknown"});
    check_invalid({"--version", "--help"});
    check_invalid({"dns", "https://safal.me"});
    check_invalid({"dns", "bad..host"});
    check_invalid({"dns", "-bad.host"});
    check_invalid({"dns", "safal.me", "--type", "INVALID"});
    check_invalid({"dns", "safal.me", "--server", "not-an-ip"});
    check_invalid({"dns", "safal.me", "--timeout", "0"});
    check_invalid({"dns", "safal.me", "--timeout", "2s"});
    check_invalid({"dns", "safal.me", "--timeout", "31"});
    check_invalid({"dns", "safal.me", "--type"});
    check_invalid({"dns", "safal.me", "--type", "A", "--type", "A"});
    {
        std::ostringstream output, errors;
        bool called = false;
        const auto resolver = [&](const netx::DnsOptions& options) {
            called = true;
            expect(options.host == "safal.me", "DNS receives hostname");
            expect(options.type == "A", "DNS defaults to A");
            expect(options.server.empty(), "DNS defaults to system resolver");
            expect(options.timeout_seconds == 2, "DNS default timeout");
            return netx::DnsResult{{{"76.76.21.21", 60}}, "", 1.25};
        };
        expect(netx::run_cli({"dns", "safal.me"}, output, errors, resolver) == 0,
               "DNS command succeeds");
        expect(called, "DNS command invokes resolver");
        expect(output.str().find("76.76.21.21  TTL 60s") != std::string::npos,
               "DNS prints address and TTL");
        expect(output.str().find("1.25 ms") != std::string::npos, "DNS prints timing");
        expect(errors.str().empty(), "successful DNS has no errors");
    }
    {
        std::ostringstream output, errors;
        const auto resolver = [&](const netx::DnsOptions& options) {
            expect(options.type == "AAAA", "DNS receives requested type");
            expect(options.server == "127.0.0.1", "DNS receives server");
            expect(options.timeout_seconds == 1, "DNS receives timeout");
            return netx::DnsResult{{}, "NXDOMAIN: domain does not exist", 1};
        };
        expect(netx::run_cli({"dns", "missing.test", "--type", "AAAA", "--server",
                             "127.0.0.1", "--timeout", "1"}, output, errors, resolver) == 1,
               "DNS lookup failure returns 1");
        expect(output.str().empty(), "failed DNS leaves stdout empty");
        expect(errors.str().find("NXDOMAIN") != std::string::npos, "DNS failure explains cause");
    }
    return failures == 0 ? 0 : 1;
}
