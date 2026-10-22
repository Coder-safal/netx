#pragma once

#include <map>
#include <iosfwd>
#include <string>
#include <vector>
#include <utility>

namespace netx {
enum class Status { pass, warn, fail, skipped };
struct Result {
    explicit Result(std::string name) : check(std::move(name)) {}
    std::string check;
    Status status = Status::pass;
    std::string summary;
    std::map<std::string, std::string> details;
    std::vector<std::string> hints;
    double elapsed_ms = 0;
};
struct Options {
    int timeout = 5;
    int redirects = 10;
    long body_limit = 1048576;
    int count = 4;
    int max_hops = 16;
    int port_filter = 0;
    int family = 0;
    bool established = false;
    bool chain = false;
    bool json = false;
    std::string ca_file;
    std::string ports;
};
struct Target {
    std::string url;
    std::string host;
    int port = 0;
    bool secure = false;
};
Target parse_target(const std::string& input, const std::string& default_scheme = "https");
Result http_check(const Target& target, const Options& options);
Result tls_check(const Target& target, const Options& options);
std::vector<Result> tcp_checks(const Target& target, const Options& options);
Result ports_check(const Options& options);
Result ping_check(const Target& target, const Options& options);
Result trace_check(const Target& target, const Options& options);
std::string status_name(Status status);
int result_exit(const std::vector<Result>& results);
void render_results(const std::vector<Result>& results, bool json, std::ostream& output);
}
