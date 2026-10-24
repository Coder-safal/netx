#include "netx/checks.hpp"

#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <ctime>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>

namespace netx {
namespace {
void initialize() {
    static const auto initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (initialized != CURLE_OK) throw std::runtime_error("Cannot initialize libcurl");
}
using Curl = std::unique_ptr<CURL, decltype(&curl_easy_cleanup)>;
using Url = std::unique_ptr<CURLU, decltype(&curl_url_cleanup)>;
std::string part(CURLU* url, CURLUPart name, unsigned flags = 0) {
    char* text = nullptr;
    if (curl_url_get(url, name, &text, flags) != CURLUE_OK) return {};
    std::string value(text);
    curl_free(text);
    return value;
}
std::string milliseconds(double seconds) {
    std::ostringstream output;
    output.precision(3);
    output << std::fixed << seconds * 1000 << " ms";
    return output.str();
}
void common(CURL* curl, const Target& target, const Options& options, char* error) {
    curl_easy_setopt(curl, CURLOPT_URL, target.url.c_str());
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(options.timeout) * 1000);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options.timeout) * 1000);
    // Local diagnostics should measure the target directly rather than an environment proxy.
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "netx");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (!options.ca_file.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, options.ca_file.c_str());
    if (options.family == 4) curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    if (options.family == 6) curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
}
void timings(CURL* curl, Result& result) {
    double dns = 0, connect = 0, tls = 0, first = 0, total = 0;
    curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &dns);
    curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &connect);
    curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &tls);
    curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &first);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);
    result.elapsed_ms = total * 1000;
    result.details["dns"] = milliseconds(dns);
    result.details["connect"] = milliseconds(std::max(0.0, connect - dns));
    result.details["tls"] = milliseconds(tls > 0 ? std::max(0.0, tls - connect) : 0);
    result.details["first_byte"] = milliseconds(first);
    result.details["total"] = milliseconds(total);
    char* address = nullptr;
    curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &address);
    if (address) result.details["address"] = address;
}
void failure(Result& result, CURLcode code, const char* error) {
    result.status = Status::fail;
    result.summary = *error ? error : curl_easy_strerror(code);
    switch (code) {
    case CURLE_COULDNT_RESOLVE_HOST: result.hints.push_back("Check the hostname and DNS configuration."); break;
    case CURLE_COULDNT_CONNECT: result.hints.push_back("Check the service, listening port, and firewall."); break;
    case CURLE_OPERATION_TIMEDOUT: result.hints.push_back("The step timed out; check routing/firewall or increase --timeout."); break;
    case CURLE_PEER_FAILED_VERIFICATION: result.hints.push_back("Check the certificate hostname, expiry, and issuer trust."); break;
    default: break;
    }
}
struct Body {
    std::size_t used = 0;
    std::size_t limit;
    bool exceeded = false;
};
std::size_t discard(char*, std::size_t size, std::size_t count, void* pointer) {
    auto& body = *static_cast<Body*>(pointer);
    const auto amount = size * count;
    if (amount > body.limit - body.used) {
        body.exceeded = true;
        return 0;
    }
    body.used += amount;
    return amount;
}
struct Headers {
    std::string statuses;
    std::string location;
    std::size_t used = 0;
};
std::size_t header(char* data, std::size_t size, std::size_t count, void* pointer) {
    const auto amount = size * count;
    auto& headers = *static_cast<Headers*>(pointer);
    headers.used += amount;
    if (headers.used > 65536) return 0;
    std::string line(data, amount);
    if (line.rfind("HTTP/", 0) == 0) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!headers.statuses.empty()) headers.statuses += " -> ";
        headers.statuses += line;
        headers.location.clear();
    }
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
        auto name = line.substr(0, colon);
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
        if (name == "location") {
            auto value = line.substr(colon + 1);
            const auto first = value.find_first_not_of(" \t");
            const auto last = value.find_last_not_of(" \t\r\n");
            headers.location = first == std::string::npos ? "" : value.substr(first, last - first + 1);
        }
    }
    return amount;
}
}

Target parse_target(const std::string& input, const std::string& default_scheme) {
    initialize();
    if (input.empty() || input.front() == '-' || input.find_first_of("\r\n\t ") != std::string::npos)
        throw std::invalid_argument("expected a hostname or HTTP(S) URL");
    const auto value = input.find("://") == std::string::npos ? default_scheme + "://" + input : input;
    Url url(curl_url(), curl_url_cleanup);
    if (!url || curl_url_set(url.get(), CURLUPART_URL, value.c_str(), 0) != CURLUE_OK)
        throw std::invalid_argument("invalid hostname or URL; bracket IPv6 addresses");
    const auto scheme = part(url.get(), CURLUPART_SCHEME);
    if (scheme != "http" && scheme != "https") throw std::invalid_argument("only HTTP and HTTPS URLs are supported");
    if (!part(url.get(), CURLUPART_USER).empty() || !part(url.get(), CURLUPART_PASSWORD).empty())
        throw std::invalid_argument("URLs containing credentials are not supported");
    Target result;
    result.url = part(url.get(), CURLUPART_URL);
    result.host = part(url.get(), CURLUPART_HOST);
    if (result.host.empty()) throw std::invalid_argument("missing hostname");
    if (result.host.front() == '[') result.host = result.host.substr(1, result.host.size() - 2);
    result.port = std::stoi(part(url.get(), CURLUPART_PORT, CURLU_DEFAULT_PORT));
    if (result.port < 1 || result.port > 65535) throw std::invalid_argument("port must be 1 to 65535");
    result.secure = scheme == "https";
    return result;
}

Result http_check(const Target& target, const Options& options) {
    initialize();
    Result result{"HTTP"};
    Curl curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) throw std::runtime_error("Cannot allocate HTTP client");
    char error[CURL_ERROR_SIZE]{};
    common(curl.get(), target, options, error);
    Body body{0, static_cast<std::size_t>(options.body_limit), false};
    Headers headers;
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, discard);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, header);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &headers);
    std::set<std::string> visited;
    std::string current = target.url;
    const auto started = std::chrono::steady_clock::now();
    int redirects = 0;
    while (true) {
        const auto remaining = options.timeout * 1000 - std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (remaining <= 0) {
            failure(result, CURLE_OPERATION_TIMEDOUT, "HTTP request timed out");
            break;
        }
        if (!visited.insert(current).second) {
            result.status = Status::fail;
            result.summary = "Redirect loop detected";
            break;
        }
        curl_easy_setopt(curl.get(), CURLOPT_URL, current.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(remaining));
        headers.location.clear();
        error[0] = '\0';
        const auto code = curl_easy_perform(curl.get());
        timings(curl.get(), result);
        long status = 0;
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
        result.details["status"] = std::to_string(status);
        if (code != CURLE_OK) {
            failure(result, code, error);
            if (body.exceeded) result.summary = "Response body exceeds --max-body limit";
            break;
        }
        const bool redirect = status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
        if (!redirect || headers.location.empty()) {
            result.status = status >= 400 ? Status::fail : Status::pass;
            result.summary = "HTTP " + std::to_string(status) + " from " + current;
            if (status >= 400) result.hints.push_back("The server responded; inspect the application route and server logs.");
            break;
        }
        if (redirects++ >= options.redirects) {
            result.status = Status::fail;
            result.summary = "Redirect limit exceeded";
            break;
        }
        Url next(curl_url(), curl_url_cleanup);
        if (!next || curl_url_set(next.get(), CURLUPART_URL, current.c_str(), 0) != CURLUE_OK ||
            curl_url_set(next.get(), CURLUPART_URL, headers.location.c_str(), 0) != CURLUE_OK) {
            result.status = Status::fail;
            result.summary = "Invalid redirect URL";
            break;
        }
        try { current = parse_target(part(next.get(), CURLUPART_URL)).url; }
        catch (const std::exception& exception) {
            result.status = Status::fail;
            result.summary = exception.what();
            break;
        }
    }
    result.details["redirect_chain"] = headers.statuses;
    result.details["body_bytes"] = std::to_string(body.used);
    result.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    result.details["total"] = milliseconds(result.elapsed_ms / 1000);
    return result;
}

Result tls_check(const Target& target, const Options& options) {
    initialize();
    Result result{"TLS"};
    const auto authority = (target.host.find(':') != std::string::npos ? "[" + target.host + "]" : target.host)
                         + ":" + std::to_string(target.port);
    const auto secure_target = parse_target("https://" + authority);
    Curl curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) throw std::runtime_error("Cannot allocate TLS client");
    char error[CURL_ERROR_SIZE]{};
    common(curl.get(), secure_target, options, error);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_CERTINFO, 1L);
    const auto code = curl_easy_perform(curl.get());
    timings(curl.get(), result);
    if (code != CURLE_OK) {
        failure(result, code, error);
        result.details["hostname_and_trust"] = "verification failed or handshake incomplete";
        return result;
    }
    result.summary = "Verified TLS handshake with " + authority;
    result.details["hostname_match"] = "PASS";
    result.details["trust_chain"] = "PASS";
    curl_certinfo* certificates = nullptr;
    curl_easy_getinfo(curl.get(), CURLINFO_CERTINFO, &certificates);
    if (!certificates || certificates->num_of_certs < 1) {
        result.status = Status::warn;
        result.summary = "TLS verified, but this backend did not expose certificate dates";
        return result;
    }
    bool expiry_found = false;
    for (int index = 0; index < certificates->num_of_certs; ++index) {
        for (auto* field = certificates->certinfo[index]; field; field = field->next) {
            const std::string value(field->data);
            const auto colon = value.find(':');
            if (colon == std::string::npos) continue;
            const auto name = value.substr(0, colon);
            const auto data = value.substr(colon + 1);
            if (index == 0 && (name == "Start date" || name == "Expire date" || name == "Subject" || name == "Issuer"))
                result.details[name] = data;
            if (index == 0 && name == "Expire date") {
                const auto expires = curl_getdate(data.c_str(), nullptr);
                if (expires >= 0) {
                    expiry_found = true;
                    const double days = std::difftime(expires, std::time(nullptr)) / 86400;
                    result.details["days_left"] = std::to_string(static_cast<long>(std::floor(days)));
                    if (days < 0) { result.status = Status::fail; result.summary = "Certificate has expired"; }
                    else if (days <= 30) {
                        result.status = Status::warn;
                        result.summary = "Certificate expires within 30 days";
                        result.hints.push_back("Renew the certificate before it expires.");
                    }
                }
            }
            if (options.chain && (name == "Subject" || name == "Issuer" || name == "Cert"))
                result.details["chain_" + std::to_string(index) + "_" + name] = data;
        }
    }
    if (!expiry_found && result.status == Status::pass) {
        result.status = Status::warn;
        result.summary = "TLS verified, but certificate expiry could not be read";
    }
    return result;
}

std::vector<Result> tcp_checks(const Target& target, const Options& options) {
    initialize();
    std::vector<int> ports;
    if (options.ports.empty()) ports.push_back(target.port);
    else {
        std::istringstream input(options.ports);
        std::string value;
        while (std::getline(input, value, ',')) ports.push_back(std::stoi(value));
    }
    std::vector<Result> results;
    for (const auto port : ports) {
        for (const int family : {4, 6}) {
            if (options.family && family != options.family) continue;
            const auto host = target.host.find(':') != std::string::npos ? "[" + target.host + "]" : target.host;
            const auto tcp_target = parse_target("http://" + host + ":" + std::to_string(port));
            Curl curl(curl_easy_init(), curl_easy_cleanup);
            if (!curl) throw std::runtime_error("Cannot allocate TCP client");
            Options attempt = options;
            attempt.family = family;
            char error[CURL_ERROR_SIZE]{};
            common(curl.get(), tcp_target, attempt, error);
            curl_easy_setopt(curl.get(), CURLOPT_CONNECT_ONLY, 1L);
            Result result{"TCP/IPv" + std::to_string(family)};
            const auto code = curl_easy_perform(curl.get());
            timings(curl.get(), result);
            if (code != CURLE_OK) {
                if (code == CURLE_COULDNT_RESOLVE_HOST) {
                    result.status = Status::skipped;
                    result.summary = "No IPv" + std::to_string(family) + " address available for " + target.host;
                } else failure(result, code, error);
            } else result.summary = "Connected to " + target.host + ":" + std::to_string(port);
            result.details["port"] = std::to_string(port);
            results.push_back(std::move(result));
        }
    }
    return results;
}
}
