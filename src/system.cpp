#include "netx/checks.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace netx {
namespace {
struct Process {
    int exit = 0;
    bool timeout = false;
    std::string output;
};
Process run(const std::vector<std::string>& command, int timeout_seconds) {
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) != 0) throw std::runtime_error("Cannot create command output pipe");
    std::vector<char*> arguments;
    for (const auto& argument : command) arguments.push_back(const_cast<char*>(argument.c_str()));
    arguments.push_back(nullptr);
    const auto child = fork();
    if (child < 0) {
        close(pipes[0]); close(pipes[1]);
        throw std::runtime_error("Cannot start diagnostic helper");
    }
    if (child == 0) {
        setpgid(0, 0);
        dup2(pipes[1], STDOUT_FILENO);
        dup2(pipes[1], STDERR_FILENO);
        close(pipes[0]); close(pipes[1]);
        setenv("LC_ALL", "C", 1);
        execvp(arguments[0], arguments.data());
        _exit(errno == ENOENT ? 127 : 126);
    }
    close(pipes[1]);
    setpgid(child, child);
    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    Process result;
    int status = 0;
    bool finished = false;
    const auto start = std::chrono::steady_clock::now();
    while (true) {
        std::array<char, 4096> buffer{};
        ssize_t count;
        while ((count = read(pipes[0], buffer.data(), buffer.size())) > 0) {
            if (result.output.size() < 262144)
                result.output.append(buffer.data(), std::min<std::size_t>(count, 262144 - result.output.size()));
        }
        if (!finished) finished = waitpid(child, &status, WNOHANG) == child;
        if (finished && count == 0) break;
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(timeout_seconds)) {
            result.timeout = true;
            kill(-child, SIGKILL);
            if (!finished) while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
            break;
        }
        pollfd descriptor{pipes[0], POLLIN, 0};
        poll(&descriptor, 1, 25);
    }
    close(pipes[0]);
    result.exit = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return result;
}
bool permission_error(const Process& process) {
    return process.exit == 126 || process.output.find("permitted") != std::string::npos ||
           process.output.find("Permission denied") != std::string::npos;
}
std::string endpoint(const std::string& value, bool ipv6) {
    const auto colon = value.find(':');
    if (colon == std::string::npos) return value;
    const auto address = value.substr(0, colon);
    std::array<unsigned char, 16> bytes{};
    const std::size_t words = ipv6 ? 4 : 1;
    if (address.size() != words * 8) return value;
    for (std::size_t i = 0; i < words; ++i) {
        const auto word = static_cast<std::uint32_t>(std::stoul(address.substr(i * 8, 8), nullptr, 16));
        std::memcpy(bytes.data() + i * 4, &word, 4);
    }
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (!inet_ntop(ipv6 ? AF_INET6 : AF_INET, bytes.data(), buffer.data(), buffer.size())) return value;
    return (ipv6 ? "[" + std::string(buffer.data()) + "]" : std::string(buffer.data())) +
           ":" + std::to_string(std::stoi(value.substr(colon + 1), nullptr, 16));
}
}

Result ports_check(const Options& options) {
    Result result{"PORTS"};
    const auto start = std::chrono::steady_clock::now();
    std::unordered_map<std::string, std::string> owners;
    bool denied = false;
    std::error_code error;
    for (const auto& process : std::filesystem::directory_iterator("/proc", error)) {
        const auto pid = process.path().filename().string();
        if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos) continue;
        std::ifstream name_file(process.path() / "comm");
        std::string name;
        std::getline(name_file, name);
        std::error_code fd_error;
        auto descriptors = std::filesystem::directory_iterator(process.path() / "fd", fd_error);
        if (fd_error == std::errc::permission_denied) denied = true;
        for (const auto& descriptor : descriptors) {
            std::error_code link_error;
            const auto link = std::filesystem::read_symlink(descriptor.path(), link_error).string();
            if (link_error == std::errc::permission_denied) denied = true;
            if (link.rfind("socket:[", 0) == 0 && link.back() == ']')
                owners[link.substr(8, link.size() - 9)] = name + " (pid " + pid + ")";
        }
    }
    int files = 0;
    std::size_t rows = 0;
    for (const std::string protocol : {"tcp", "tcp6", "udp", "udp6"}) {
        const bool ipv6 = protocol.back() == '6';
        if ((options.family == 4 && ipv6) || (options.family == 6 && !ipv6)) continue;
        std::ifstream input("/proc/net/" + protocol);
        if (!input) continue;
        ++files;
        std::string line;
        std::getline(input, line);
        while (std::getline(input, line)) {
            std::istringstream parser(line);
            std::vector<std::string> fields;
            std::string field;
            while (parser >> field) fields.push_back(field);
            if (fields.size() < 10) continue;
            const bool tcp = protocol.rfind("tcp", 0) == 0;
            const auto state = fields[3];
            if (options.established ? !(tcp && state == "01") : !(tcp ? state == "0A" : state == "07")) continue;
            const auto colon = fields[1].find(':');
            if (colon == std::string::npos) continue;
            const auto port = std::stoi(fields[1].substr(colon + 1), nullptr, 16);
            if (options.port_filter && port != options.port_filter) continue;
            const auto owner = owners.find(fields[9]);
            const auto program = owner != owners.end() ? owner->second :
                                 denied ? "unknown (permission denied)" : "unknown";
            result.details[std::to_string(++rows)] = protocol + " " + endpoint(fields[1], ipv6) +
                " -> " + endpoint(fields[2], ipv6) + " " + (options.established ? "ESTABLISHED" : tcp ? "LISTEN" : "BOUND") +
                " " + program;
        }
    }
    if (files == 0) {
        result.status = Status::skipped;
        result.summary = "Cannot read Linux /proc/net socket tables";
        result.hints.push_back("Run on Linux with /proc mounted and readable.");
    } else result.summary = std::to_string(rows) + " matching sockets";
    result.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    return result;
}

Result ping_check(const Target& target, const Options& options) {
    Result result{"PING"};
    const auto start = std::chrono::steady_clock::now();
    std::vector<std::string> command{"ping", "-n", "-c", std::to_string(options.count), "-i", "0.2", "-W",
                                     std::to_string(options.timeout)};
    if (options.family) command.push_back(options.family == 4 ? "-4" : "-6");
    command.push_back("--");
    command.push_back(target.host);
    const auto process = run(command, options.count * options.timeout + options.count + 2);
    result.details["method"] = "ICMP";
    if (process.exit == 127 || permission_error(process)) {
        result.details["method"] = "TCP fallback: ICMP helper missing or permission denied";
        Options attempt = options;
        std::vector<double> samples;
        for (int i = 0; i < options.count; ++i) {
            for (const auto& tcp : tcp_checks(target, attempt)) {
                if (tcp.status == Status::pass) { samples.push_back(tcp.elapsed_ms); break; }
            }
        }
        result.details["packet_loss"] = std::to_string(100.0 * (options.count - samples.size()) / options.count) + "% (TCP attempts)";
        if (samples.empty()) {
            result.status = Status::fail;
            result.summary = "ICMP unavailable and TCP fallback could not connect";
        } else {
            result.status = Status::warn;
            result.summary = "Reachable via TCP; ICMP measurement unavailable";
            const auto mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
            double variance = 0;
            for (const auto sample : samples) variance += (sample - mean) * (sample - mean);
            result.details["latency_mean_ms"] = std::to_string(mean);
            result.details["jitter_stddev_ms"] = std::to_string(std::sqrt(variance / samples.size()));
        }
    } else {
        result.details["probe_output"] = process.output;
        result.status = process.exit == 0 && !process.timeout ? Status::pass : Status::fail;
        result.summary = process.timeout ? "ICMP probe deadline exceeded" :
                         process.exit == 0 ? "ICMP replies received from " + target.host : "ICMP probe failed for " + target.host;
        std::smatch match;
        if (std::regex_search(process.output, match, std::regex("([0-9.]+)% packet loss"))) {
            result.details["packet_loss"] = match[1];
            if (result.status == Status::pass && match[1] != "0") result.status = Status::warn;
        }
        if (std::regex_search(process.output, match, std::regex("= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms"))) {
            result.details["latency_min_ms"] = match[1];
            result.details["latency_mean_ms"] = match[2];
            result.details["latency_max_ms"] = match[3];
            result.details["jitter_stddev_ms"] = match[4];
        }
    }
    result.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    return result;
}

Result trace_check(const Target& target, const Options& options) {
    Result result{"TRACE"};
    const auto start = std::chrono::steady_clock::now();
    std::vector<std::string> command{"traceroute", "-n", "-q", "1", "-m", std::to_string(options.max_hops),
                                     "-w", std::to_string(options.timeout)};
    if (options.family) command.push_back(options.family == 4 ? "-4" : "-6");
    command.push_back("--");
    command.push_back(target.host);
    const auto process = run(command, options.max_hops * options.timeout + 3);
    result.details["hops"] = process.output;
    if (process.exit == 127 || permission_error(process)) {
        result.status = Status::skipped;
        result.summary = process.exit == 127 ? "traceroute helper is not installed" : "Route probing permission denied";
        result.hints.push_back("Install traceroute or ask the system administrator to allow route probes.");
    } else if (process.timeout || process.exit != 0) {
        result.status = Status::fail;
        result.summary = process.timeout ? "Route probe deadline exceeded" : "Route probe failed";
    } else {
        std::string destination = target.host;
        std::smatch match;
        if (std::regex_search(process.output, match, std::regex("traceroute to .* \\(([^)]+)\\)"))) destination = match[1];
        std::istringstream lines(process.output);
        std::string line, last;
        while (std::getline(lines, line)) if (!line.empty()) last = line;
        const bool reached = last.find(" " + destination + " ") != std::string::npos;
        result.status = reached && process.output.find('*') == std::string::npos && process.output.find('!') == std::string::npos
                      ? Status::pass : Status::warn;
        result.summary = reached ? "Route reached " + target.host : "Destination was not confirmed within the hop limit";
        if (result.status == Status::warn) result.hints.push_back("Some hops may filter probes or the route may be incomplete; review the hop output.");
    }
    result.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    return result;
}
}
