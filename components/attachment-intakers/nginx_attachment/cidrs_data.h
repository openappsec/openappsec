#ifndef __CIDRS_DATA_H__
#define __CIDRS_DATA_H__

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include "maybe_res.h"
#include "connkey.h"

class CIDRSData
{
public:
    CIDRSData(const std::string &str_cidr);
    bool contains(const std::string &source_ip) const;

private:
    bool matchCidr(const in_addr &address, const in_addr &net) const;
    bool matchCidr(const in6_addr &address, const in6_addr &network) const;

    IPAddr      ip_addr;
    uint8_t     network_bits;
    bool        valid_cidr = false;
};

#endif // __CIDRS_DATA_H__
