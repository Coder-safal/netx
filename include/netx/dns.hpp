#pragma once

#include <string>
#include <vector>

namespace netx {
struct DnsOptions {
    std::string host;
    std::string type = "A";
    std::string server;
    int timeout_seconds = 2;
};
struct DnsRecord {
    std::string address;
    unsigned long ttl;
};
struct DnsResult {
    std::vector<DnsRecord> records;
    std::string error;
    double elapsed_ms = 0;
};
DnsResult lookup_dns(const DnsOptions& options);
int dns_type(const std::string& name);
// Parse address answers separately so malformed packets can be tested offline.
DnsResult parse_dns_response(const unsigned char* packet, int size, int type);
}
