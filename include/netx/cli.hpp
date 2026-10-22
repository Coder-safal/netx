#pragma once

#include <iosfwd>
#include <string_view>
#include <vector>
#include <functional>
#include "netx/dns.hpp"

namespace netx {
// Arguments exclude the executable name. Return a process exit code.
int run_cli(const std::vector<std::string_view>& arguments,
            std::ostream& output, std::ostream& errors,
            const std::function<DnsResult(const DnsOptions&)>& resolver = lookup_dns);
}
