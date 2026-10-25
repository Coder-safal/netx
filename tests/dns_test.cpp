#include "netx/dns.hpp"

#include <arpa/nameser.h>
#include <iostream>
#include <string>
#include <vector>

namespace {
int failures = 0;
void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}
std::vector<unsigned char> response(int type) {
    // A single question for example.test and an answer using DNS name compression.
    std::vector<unsigned char> packet = {
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0,
        0, static_cast<unsigned char>(type), 0, 1,
        0xc0, 0x0c, 0, static_cast<unsigned char>(type), 0, 1,
        0, 0, 0, 60, 0, static_cast<unsigned char>(type == ns_t_a ? 4 : 16)
    };
    if (type == ns_t_a) packet.insert(packet.end(), {192, 0, 2, 1});
    else packet.insert(packet.end(), {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    return packet;
}
netx::DnsResult parse(const std::vector<unsigned char>& packet, int type = ns_t_a) {
    return netx::parse_dns_response(packet.data(), static_cast<int>(packet.size()), type);
}
}

int main() {
    auto packet = response(ns_t_a);
    auto result = parse(packet);
    expect(result.error.empty(), "valid A response succeeds");
    expect(result.records.size() == 1, "one A record");
    if (!result.records.empty()) {
        expect(result.records[0].address == "192.0.2.1", "A address decoded");
        expect(result.records[0].ttl == 60, "TTL decoded");
    }
    result = parse(response(ns_t_aaaa), ns_t_aaaa);
    expect(result.error.empty() && result.records.size() == 1, "valid AAAA response succeeds");
    if (!result.records.empty()) expect(result.records[0].address == "2001:db8::1", "IPv6 decoded");
    expect(!parse({}).error.empty(), "empty packet rejected");
    packet.pop_back();
    expect(!parse(packet).error.empty(), "truncated record rejected");
    packet = response(ns_t_a);
    packet[3] = 0x83;
    expect(parse(packet).error.find("NXDOMAIN") != std::string::npos, "NXDOMAIN classified");
    packet[3] = 0x82;
    expect(parse(packet).error.find("SERVFAIL") != std::string::npos, "SERVFAIL classified");
    packet = response(ns_t_a);
    packet[2] |= 0x02;
    expect(!parse(packet).error.empty(), "truncated flag rejected");
    packet = response(ns_t_a);
    expect(!parse(packet, ns_t_aaaa).error.empty(), "missing requested record type reported");
    packet[packet.size() - 5] = 3;
    expect(!parse(packet).error.empty(), "invalid address length rejected");
    return failures == 0 ? 0 : 1;
}
