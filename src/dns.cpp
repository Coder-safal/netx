#include "netx/dns.hpp"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>

#include <array>
#include <chrono>
#include <cerrno>
#include <map>
#include <sstream>

namespace netx {
int dns_type(const std::string& name) {
    static const std::map<std::string, int> types{{"A", ns_t_a}, {"AAAA", ns_t_aaaa},
        {"CNAME", ns_t_cname}, {"MX", ns_t_mx}, {"NS", ns_t_ns}, {"TXT", ns_t_txt},
        {"SOA", ns_t_soa}, {"CAA", 257}, {"PTR", ns_t_ptr}};
    const auto found = types.find(name);
    return found == types.end() ? 0 : found->second;
}
DnsResult parse_dns_response(const unsigned char* packet, int size, int type) {
    DnsResult result;
    ns_msg message{};
    if (size < NS_HFIXEDSZ || ns_initparse(packet, size, &message) < 0) {
        result.error = "Malformed DNS response";
        return result;
    }
    const int code = ns_msg_getflag(message, ns_f_rcode);
    if (code != ns_r_noerror) {
        result.error = code == ns_r_nxdomain ? "NXDOMAIN: domain does not exist" :
                       code == ns_r_servfail ? "SERVFAIL: resolver failed" :
                       "DNS server returned error " + std::to_string(code);
        return result;
    }
    if (ns_msg_getflag(message, ns_f_tc)) {
        result.error = "Truncated DNS response";
        return result;
    }
    for (int index = 0; index < ns_msg_count(message, ns_s_an); ++index) {
        ns_rr record{};
        if (ns_parserr(&message, ns_s_an, index, &record) < 0) {
            result.records.clear();
            result.error = "Malformed DNS answer";
            return result;
        }
        if (static_cast<int>(ns_rr_type(record)) != type || ns_rr_class(record) != ns_c_in) {
            continue;
        }
        const auto* data = ns_rr_rdata(record);
        const auto length = static_cast<unsigned>(ns_rr_rdlen(record));
        std::string text;
        bool valid = true;
        if (type == ns_t_a || type == ns_t_aaaa) {
            if (length != (type == ns_t_a ? 4 : 16)) valid = false;
            else {
                std::array<char, INET6_ADDRSTRLEN> address{};
                if (!inet_ntop(type == ns_t_a ? AF_INET : AF_INET6, data, address.data(), address.size())) valid = false;
                else text = address.data();
            }
        } else if (type == ns_t_txt) {
            for (unsigned offset = 0; offset < length;) {
                const unsigned count = data[offset++];
                if (count > length - offset) { valid = false; break; }
                if (!text.empty()) text += ' ';
                text += '"' + std::string(reinterpret_cast<const char*>(data + offset), count) + '"';
                offset += count;
            }
        } else if (type == 257) {
            if (length < 2 || data[1] > length - 2) valid = false;
            else text = std::to_string(data[0]) + " " + std::string(reinterpret_cast<const char*>(data + 2), data[1]) +
                " \"" + std::string(reinterpret_cast<const char*>(data + 2 + data[1]), length - 2 - data[1]) + "\"";
        } else {
            unsigned offset = type == ns_t_mx ? 2 : 0;
            if (offset >= length) valid = false;
            if (valid && type == ns_t_mx) text = std::to_string(ns_get16(data)) + " ";
            const int names = type == ns_t_soa ? 2 : 1;
            for (int i = 0; valid && i < names; ++i) {
                std::array<char, NS_MAXDNAME> name{};
                const auto consumed = dn_expand(packet, packet + size, data + offset, name.data(), name.size());
                if (consumed < 0 || offset + consumed > length) { valid = false; break; }
                if (i) text += ' ';
                text += name.data();
                offset += consumed;
            }
            if (valid && type == ns_t_soa) {
                if (offset + 20 != length) valid = false;
                else for (int i = 0; i < 5; ++i) text += " " + std::to_string(ns_get32(data + offset + i * 4));
            } else if (offset != length) valid = false;
        }
        if (!valid) {
            result.records.clear();
            result.error = "Malformed DNS record data";
            return result;
        }
        result.records.push_back({text, ns_rr_ttl(record)});
    }
    if (result.records.empty()) {
        result.error = "No records of the requested type";
    }
    return result;
}

DnsResult lookup_dns(const DnsOptions& options) {
    DnsResult result;
    struct __res_state state{};
    if (res_ninit(&state) != 0) {
        result.error = "Cannot initialize the system DNS resolver";
        return result;
    }
    struct ResolverGuard {
        struct __res_state* state;
        ~ResolverGuard() { res_nclose(state); }
    } guard{&state};
    state.retrans = options.timeout_seconds;
    state.retry = 1;
    // Preserve negative DNS replies for diagnostics instead of silently retrying them.
    state.pfcode = 1;
    if (!options.server.empty()) {
        sockaddr_in server{};
        server.sin_family = AF_INET;
        server.sin_port = htons(NS_DEFAULTPORT);
        auto address = options.server;
        const auto colon = address.find(':');
        if (colon != std::string::npos) {
            const auto port = address.substr(colon + 1);
            try {
                std::size_t consumed = 0;
                const auto number = std::stoi(port, &consumed);
                if (number < 1 || number > 65535 || consumed != port.size()) throw std::invalid_argument("port");
                server.sin_port = htons(number);
            } catch (...) { result.error = "Invalid DNS server port"; return result; }
            address.resize(colon);
        }
        if (inet_pton(AF_INET, address.c_str(), &server.sin_addr) != 1) {
            result.error = "DNS server must be an IPv4 address";
            return result;
        }
        state.nsaddr_list[0] = server;
        state.nscount = 1;
    }
    const int type = dns_type(options.type);
    if (!type) { result.error = "Unsupported DNS type"; return result; }
    std::string host = options.host;
    if (type == ns_t_ptr) {
        in_addr ipv4{};
        in6_addr ipv6{};
        if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
            const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4);
            host.clear();
            for (int i = 3; i >= 0; --i) host += std::to_string(bytes[i]) + ".";
            host += "in-addr.arpa";
        } else if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
            constexpr char hex[] = "0123456789abcdef";
            host.clear();
            for (int i = 15; i >= 0; --i) {
                host += hex[ipv6.s6_addr[i] & 15]; host += '.';
                host += hex[ipv6.s6_addr[i] >> 4]; host += '.';
            }
            host += "ip6.arpa";
        }
    }
    std::array<unsigned char, 65536> packet{};
    std::array<unsigned char, NS_PACKETSZ> query{};
    const int query_size = res_nmkquery(&state, ns_o_query, host.c_str(), ns_c_in, type,
                                      nullptr, 0, nullptr, query.data(), query.size());
    if (query_size < 0) { result.error = "Cannot construct DNS query"; return result; }
    const auto start = std::chrono::steady_clock::now();
    errno = 0;
    const int size = res_nsend(&state, query.data(), query_size, packet.data(), packet.size());
    if (size < 0) {
        result.error = errno == ETIMEDOUT ? "DNS timeout: resolver did not respond" :
                                           "DNS resolver unavailable or response invalid";
    } else if (size > static_cast<int>(packet.size())) {
        result.error = "DNS response exceeds the buffer limit";
    } else {
        result = parse_dns_response(packet.data(), size, type);
    }
    result.elapsed_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
    return result;
}
}
