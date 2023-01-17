#include "cidrs_data.h"

#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT_PARSER);


bool
CIDRSData::matchCidr(const in_addr &address, const in_addr &network) const
{
    if (network_bits == 0) {
        // C99 6.5.7 (3): u32 << 32 is undefined behaviour
        return true;
    }
    return !((address.s_addr ^ network.s_addr) & htonl(0xFFFFFFFFu << (32 - network_bits)));
}

bool
CIDRSData::matchCidr(const in6_addr &address, const in6_addr &network) const
{
#ifdef __linux__
    const uint32_t *a = address.s6_addr32;
    const uint32_t *n = network.s6_addr32;
#else
    const uint32_t *a = address.__u6_addr.__u6_addr32;
    const uint32_t *n = network.__u6_addr.__u6_addr32;
#endif
    int bits_whole, bits_incomplete;
    bits_whole = network_bits >> 5;         // number of whole u32
    bits_incomplete = network_bits & 0x1F;  // number of bits in incomplete u32
    if (bits_whole) {
        if (memcmp(a, n, bits_whole << 2)) {
            return false;
        }
    }
    if (bits_incomplete) {
        uint32_t mask = htonl((0xFFFFFFFFu) << (32 - bits_incomplete));
        if ((a[bits_whole] ^ n[bits_whole]) & mask) {
            return false;
        }
    }
    return true;
}

CIDRSData::CIDRSData(const string &str_cidr)
{
    size_t processed_bits = 0;

    size_t pos = str_cidr.find_last_of('/');

    // get ip from targetCidr
    string str_prefix = pos != string::npos ? str_cidr.substr(0, pos) : str_cidr;
    // get subnet mask from targetCidr or calculate it based on ipv4 / ipv6
    string str_suffix;
    if (pos != string::npos && (pos + 1) <= str_cidr.size()) {
        str_suffix = str_cidr.substr(pos + 1);
    } else if (str_cidr.find(':') == string::npos) {
        str_suffix = "32";
    } else {
        str_suffix = "128";
    }


    int bits = -1;
    try {
        bits = stoi(str_suffix, &processed_bits);
        network_bits = (uint8_t)bits;
        // convert int to uint8_t
    } catch (...) {
        dbgWarning(D_NGINX_ATTACHMENT_PARSER)
            << "Failed to convert CIDR number of bits from string to int"
            << str_cidr;
        return;
    }

    // check if CIDR is valid
    if (processed_bits != str_suffix.length() || bits > 128 || bits < 0) {
        dbgWarning(D_NGINX_ATTACHMENT_PARSER)
            << "Failed to convert CIDR number of bits from string to int (out of range)."
            << str_cidr;
        return;
    }

    if (IPAddr::isValidIPAddr(str_prefix)) {
        ip_addr = IPAddr::createIPAddr(str_prefix).unpack();
    } else {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Failed to convert CIDR number of bits from string to int";
        return;
    }

    dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "successfully created cidr from the following string: " << str_cidr;
    valid_cidr = true;
}

bool
CIDRSData::contains(const string &source_ip) const
{
    if(!valid_cidr) {
        dbgDebug(D_NGINX_ATTACHMENT_PARSER) << "Invalid CIDR.";
        return false;
    }

    // check from which type the target ip and check if ip belongs to is mask ip
    //convert source_ip to ip v4 or v6.
    switch (ip_addr.getType()) {
        case IPType::V4: {
            struct in_addr source_inaddr;
            if (inet_pton(AF_INET, source_ip.c_str(), &source_inaddr) == 1) {
                return matchCidr(source_inaddr, ip_addr.getIPv4());
            }
            break;
        }
        case IPType::V6: {
            struct in6_addr source_inaddr6;
            if (inet_pton(AF_INET6, source_ip.c_str(), &source_inaddr6) == 1) {
                return matchCidr(source_inaddr6, ip_addr.getIPv6());
            }
            break;
        }
        default: {
            dbgWarning(D_NGINX_ATTACHMENT_PARSER) << "Unexpected ip type";
        }
    }

    return false;
}
