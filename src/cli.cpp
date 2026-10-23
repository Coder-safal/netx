#include "netx/cli.hpp"
#include "netx/checks.hpp"
#include "netx/version.hpp"

#include <arpa/inet.h>
#include <charconv>
#include <cctype>
#include <iomanip>
#include <map>
#include <ostream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace netx {
namespace {
constexpr std::string_view help =
    "netx - Linux network diagnostics\n\n"
    "Usage: netx COMMAND [TARGET] [OPTIONS]\n"
    "       netx [--help | --version]\n\n"
    "Commands:\n"
    "  dns HOST       DNS records, TTL, and lookup time\n"
    "  http URL       HTTP status, redirects, and timings\n"
    "  tls HOST       Verified TLS handshake and certificate dates\n"
    "  diagnose HOST  DNS, TCP, TLS, and HTTP with conclusions\n"
    "  check HOST     Short deployment-check summary\n"
    "  tcp HOST       Separate IPv4 and IPv6 connection checks\n"
    "  ports          Local listening TCP and bound UDP sockets\n"
    "  ping HOST      ICMP latency/loss/jitter, with TCP fallback\n"
    "  trace HOST     Route probes using traceroute\n\n"
    "Shared: --json --timeout SECONDS (1..30, default 5) -4 -6\n"
    "DNS: --type A|AAAA|CNAME|MX|NS|TXT|SOA|CAA|PTR\n"
    "     --server IPV4[:PORT] --compare IPV4,IPV4\n"
    "HTTP/diagnose/check: --max-redirects N --max-body BYTES --ca-file PATH\n"
    "TLS/diagnose/check: --chain --ca-file PATH\n"
    "TCP: --ports 80,443\n"
    "Ports: --port N --established\n"
    "Ping: --count N --port N\n"
    "Trace: --max-hops N\n"
    "Diagnose/check: --deployment (same full deployment checks)\n"
    "Help: -h, --help; version: -V, --version\n";

int integer(std::string_view value, int minimum, int maximum, const std::string& name) {
    int result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result < minimum || result > maximum)
        throw std::invalid_argument(name + " must be an integer from " + std::to_string(minimum) + " to " + std::to_string(maximum));
    return result;
}
bool valid_host(std::string host) {
    in6_addr address{};
    if (inet_pton(AF_INET6, host.c_str(), &address) == 1) return true;
    if (host.empty() || host.size() > 253) return false;
    if (host.back() == '.') host.pop_back();
    std::size_t length = 0;
    char previous = '.';
    for (unsigned char c : host) {
        if (c == '.') {
            if (!length || previous == '-') return false;
            length = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
            if ((!length && c == '-') || ++length > 63) return false;
        }
        previous = c;
    }
    return length && previous != '-';
}
void server_valid(const std::string& value) {
    const auto colon = value.find(':');
    const auto host = value.substr(0, colon);
    in_addr address{};
    if (inet_pton(AF_INET, host.c_str(), &address) != 1) throw std::invalid_argument("--server requires an IPv4 address, optionally followed by :PORT");
    if (colon != std::string::npos) integer(value.substr(colon + 1), 1, 65535, "DNS server port");
}
std::vector<std::string> split(const std::string& value) {
    if (value.empty() || value.back() == ',') throw std::invalid_argument("empty item in comma-separated list");
    std::vector<std::string> items;
    std::istringstream input(value);
    std::string item;
    while (std::getline(input, item, ',')) {
        if (item.empty()) throw std::invalid_argument("empty item in comma-separated list");
        items.push_back(item);
    }
    if (items.size() > 32) throw std::invalid_argument("at most 32 list items are accepted");
    return items;
}
Result dns_result(const DnsOptions& options, const std::function<DnsResult(const DnsOptions&)>& resolver) {
    const auto response = resolver(options);
    Result result{"DNS"};
    result.elapsed_ms = response.elapsed_ms;
    result.summary = options.host + " (" + options.type + ")";
    result.details["server"] = options.server.empty() ? "system" : options.server;
    if (!response.error.empty()) {
        result.status = Status::fail;
        result.summary += ": " + response.error;
        result.hints.push_back("Check the hostname, requested record type, and DNS resolver.");
    } else {
        for (std::size_t index = 0; index < response.records.size(); ++index) {
            const auto& record = response.records[index];
            result.details["record_" + std::to_string(index + 1)] = record.address + "  TTL " + std::to_string(record.ttl) + "s";
        }
    }
    return result;
}
Result skipped(const std::string& check, const std::string& why) {
    Result result{check};
    result.status = Status::skipped;
    result.summary = why;
    return result;
}
std::vector<Result> diagnose(const Target& target, const Options& options,
                           const std::function<DnsResult(const DnsOptions&)>& resolver) {
    std::vector<Result> results;
    in6_addr ipv6{};
    in_addr ipv4{};
    if (inet_pton(AF_INET, target.host.c_str(), &ipv4) == 1 || inet_pton(AF_INET6, target.host.c_str(), &ipv6) == 1) {
        Result literal{"DNS"};
        literal.summary = "Target is an IP literal; DNS lookup is unnecessary";
        results.push_back(literal);
    } else {
        auto dns = dns_result({target.host, options.family == 6 ? "AAAA" : "A", "", options.timeout}, resolver);
        if (dns.status == Status::fail && options.family == 0)
            dns = dns_result({target.host, "AAAA", "", options.timeout}, resolver);
        results.push_back(dns);
    }
    bool ready = results.back().status != Status::fail;
    if (ready) {
        auto tcp = tcp_checks(target, options);
        ready = false;
        for (const auto& attempt : tcp) ready |= attempt.status == Status::pass;
        Result combined{"TCP"};
        combined.status = ready ? Status::pass : Status::fail;
        combined.summary = ready ? "Target port is reachable" : "No connection succeeded";
        for (const auto& attempt : tcp) {
            combined.details[attempt.check] = status_name(attempt.status) + ": " + attempt.summary;
            combined.elapsed_ms += attempt.elapsed_ms;
        }
        if (!ready) combined.hints.push_back("Check the listener, firewall, security group, and destination port.");
        results.push_back(combined);
    } else results.push_back(skipped("TCP", "DNS prerequisite failed"));
    if (!ready) results.push_back(skipped("TLS", "DNS/TCP prerequisite failed"));
    else if (!target.secure) results.push_back(skipped("TLS", "HTTP URL uses plaintext; TLS is not applicable"));
    else {
        results.push_back(tls_check(target, options));
        ready = results.back().status != Status::fail;
    }
    if (ready) results.push_back(http_check(target, options));
    else results.push_back(skipped("HTTP", "A DNS, TCP, or TLS prerequisite failed"));
    Result conclusion{"CONCLUSION"};
    const auto code = result_exit(results);
    conclusion.status = code == 1 ? Status::fail : code == 3 ? Status::warn : Status::pass;
    conclusion.summary = code == 1 ? "A deployment check failed; inspect the first FAIL and its hints." :
                         code == 3 ? "The endpoint responded, with warnings or inapplicable checks; review the details." :
                                     "DNS, connectivity, certificate, and HTTP checks passed.";
    results.push_back(conclusion);
    return results;
}
}

int run_cli(const std::vector<std::string_view>& arguments, std::ostream& output, std::ostream& errors,
            const std::function<DnsResult(const DnsOptions&)>& resolver) {
    try {
        if (arguments.empty() || (arguments.size() == 1 && (arguments[0] == "--help" || arguments[0] == "-h"))) {
            output << help;
            return 0;
        }
        if (arguments.size() == 1 && (arguments[0] == "--version" || arguments[0] == "-V")) {
            output << "netx " << version << '\n';
            return 0;
        }
        const std::string command(arguments[0]);
        const std::set<std::string> commands{"dns", "http", "tls", "diagnose", "check", "tcp", "ports", "ping", "trace"};
        if (!commands.count(command)) throw std::invalid_argument("unknown command or invalid top-level option: " + command);
        if (arguments.size() == 2 && (arguments[1] == "--help" || arguments[1] == "-h")) {
            output << help;
            return 0;
        }
        const std::map<std::string, std::set<std::string>> allowed{
            {"dns", {"--type", "--server", "--compare", "--timeout", "--json"}},
            {"http", {"--timeout", "--json", "--max-redirects", "--max-body", "--ca-file", "-4", "-6", "--ipv4", "--ipv6"}},
            {"tls", {"--timeout", "--json", "--chain", "--ca-file", "-4", "-6", "--ipv4", "--ipv6"}},
            {"diagnose", {"--timeout", "--json", "--chain", "--ca-file", "--max-redirects", "--max-body", "--deployment", "-4", "-6", "--ipv4", "--ipv6"}},
            {"check", {"--timeout", "--json", "--chain", "--ca-file", "--max-redirects", "--max-body", "--deployment", "-4", "-6", "--ipv4", "--ipv6"}},
            {"tcp", {"--timeout", "--json", "--ports", "-4", "-6", "--ipv4", "--ipv6"}},
            {"ports", {"--json", "--port", "--established", "-4", "-6", "--ipv4", "--ipv6"}},
            {"ping", {"--timeout", "--json", "--count", "--port", "-4", "-6", "--ipv4", "--ipv6"}},
            {"trace", {"--timeout", "--json", "--max-hops", "-4", "-6", "--ipv4", "--ipv6"}}
        };
        const std::set<std::string> flags{"--json", "--chain", "--established", "--deployment", "-4", "-6", "--ipv4", "--ipv6"};
        std::map<std::string, std::string> values;
        std::string input;
        for (std::size_t i = 1; i < arguments.size(); ++i) {
            const std::string token(arguments[i]);
            if (!token.empty() && token[0] == '-') {
                if (!allowed.at(command).count(token)) throw std::invalid_argument("unknown option for " + command + ": " + token);
                if (values.count(token)) throw std::invalid_argument("repeated option: " + token);
                if (flags.count(token)) values[token] = "true";
                else {
                    if (++i == arguments.size()) throw std::invalid_argument("missing value for " + token);
                    values[token] = arguments[i];
                }
            } else {
                if (!input.empty()) throw std::invalid_argument("expected one target");
                input = token;
            }
        }
        if ((command == "ports" && !input.empty()) || (command != "ports" && input.empty()))
            throw std::invalid_argument(command == "ports" ? "ports takes no target" : "missing target, for example: netx " + command + " safal.me");
        Options options;
        if (command == "dns") options.timeout = 2;
        if (values.count("--timeout")) options.timeout = integer(values["--timeout"], 1, 30, "--timeout");
        options.json = values.count("--json");
        options.chain = values.count("--chain");
        options.established = values.count("--established");
        const bool v4 = values.count("-4") || values.count("--ipv4");
        const bool v6 = values.count("-6") || values.count("--ipv6");
        if (v4 && v6) throw std::invalid_argument("choose either IPv4 or IPv6");
        options.family = v4 ? 4 : v6 ? 6 : 0;
        if (values.count("--ca-file")) options.ca_file = values["--ca-file"];
        if (values.count("--max-redirects")) options.redirects = integer(values["--max-redirects"], 0, 50, "--max-redirects");
        if (values.count("--max-body")) options.body_limit = integer(values["--max-body"], 1, 104857600, "--max-body");
        if (values.count("--count")) options.count = integer(values["--count"], 1, 20, "--count");
        if (values.count("--max-hops")) options.max_hops = integer(values["--max-hops"], 1, 64, "--max-hops");
        if (values.count("--port")) options.port_filter = integer(values["--port"], 1, 65535, "--port");
        if (values.count("--ports")) {
            options.ports = values["--ports"];
            for (const auto& port : split(options.ports)) integer(port, 1, 65535, "--ports entry");
        }
        std::vector<Result> results;
        if (command == "dns") {
            if (!valid_host(input)) throw std::invalid_argument("expected a DNS hostname or IP address, not a URL");
            DnsOptions dns{input, values.count("--type") ? values["--type"] : "A", "", options.timeout};
            if (!dns_type(dns.type)) throw std::invalid_argument("unsupported --type; use A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, or PTR");
            if (values.count("--server") && values.count("--compare")) throw std::invalid_argument("choose --server or --compare");
            std::vector<std::string> servers{""};
            if (values.count("--server")) servers = {values["--server"]};
            if (values.count("--compare")) servers = split(values["--compare"]);
            for (const auto& server : servers) if (!server.empty()) server_valid(server);
            for (const auto& server : servers) { dns.server = server; results.push_back(dns_result(dns, resolver)); }
        } else if (command == "ports") results.push_back(ports_check(options));
        else {
            auto target = parse_target(input);
            if (options.port_filter) target.port = options.port_filter;
            if (command == "http") results.push_back(http_check(target, options));
            else if (command == "tls") results.push_back(tls_check(target, options));
            else if (command == "tcp") results = tcp_checks(target, options);
            else if (command == "ping") results.push_back(ping_check(target, options));
            else if (command == "trace") results.push_back(trace_check(target, options));
            else results = diagnose(target, options, resolver);
        }
        if (command == "check" && !options.json) {
            for (const auto& result : results) output << status_name(result.status) << ' ' << result.check << ": " << result.summary << '\n';
        } else if (command == "dns" && !options.json && result_exit(results) == 1) {
            render_results(results, false, errors);
        } else render_results(results, options.json, output);
        return result_exit(results);
    } catch (const std::invalid_argument& exception) {
        errors << "netx: " << exception.what() << "; use --help for usage\n";
        return 2;
    } catch (const std::exception& exception) {
        errors << "netx: " << exception.what() << '\n';
        return 2;
    }
}
}
