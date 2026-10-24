#include "netx/checks.hpp"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace netx {
namespace {
std::string quote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 32 || c >= 127) out << "\\u00" << std::hex << std::setw(2)
                                      << std::setfill('0') << static_cast<int>(c) << std::dec;
            else out << static_cast<char>(c);
        }
    }
    out << '"';
    return out.str();
}
}
std::string status_name(Status status) {
    switch (status) {
    case Status::pass: return "PASS";
    case Status::warn: return "WARN";
    case Status::fail: return "FAIL";
    case Status::skipped: return "SKIPPED";
    }
    return "FAIL";
}
int result_exit(const std::vector<Result>& results) {
    bool warning = false;
    for (const auto& result : results) {
        if (result.status == Status::fail) return 1;
        warning |= result.status == Status::warn || result.status == Status::skipped;
    }
    return warning ? 3 : 0;
}
void render_results(const std::vector<Result>& results, bool json, std::ostream& output) {
    if (json) output << "{\"schema_version\":1,\"exit_code\":" << result_exit(results) << ",\"results\":[";
    bool first = true;
    for (const auto& result : results) {
        if (json) {
            if (!first) output << ',';
            first = false;
            output << "{\"check\":" << quote(result.check) << ",\"status\":" << quote(status_name(result.status))
                   << ",\"summary\":" << quote(result.summary) << ",\"elapsed_ms\":"
                   << std::fixed << std::setprecision(3) << result.elapsed_ms << ",\"details\":{";
            bool detail_first = true;
            for (const auto& item : result.details) {
                if (!detail_first) output << ',';
                detail_first = false;
                output << quote(item.first) << ':' << quote(item.second);
            }
            output << "},\"hints\":[";
            for (std::size_t i = 0; i < result.hints.size(); ++i) {
                if (i) output << ',';
                output << quote(result.hints[i]);
            }
            output << "]}";
        } else {
            output << status_name(result.status) << ' ' << result.check << ": " << result.summary << '\n';
            for (const auto& item : result.details) output << "  " << item.first << ": " << item.second << '\n';
            output << "  Lookup time: " << std::fixed << std::setprecision(2) << result.elapsed_ms << " ms\n";
            for (const auto& hint : result.hints) output << "  Hint: " << hint << '\n';
        }
    }
    if (json) output << "]}\n";
}
}
