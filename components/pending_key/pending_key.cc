#include "pending_key.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "debug.h"
#include "hash_combine.h"
#include "enum_range.h"
#include "cereal/types/memory.hpp"

using namespace std;

CEREAL_CLASS_VERSION(PendingKey, 0);

static bool
protoHasPorts(IPProto proto)
{
    return (proto==IPPROTO_TCP) || (proto==IPPROTO_UDP);
}

// Format a port numbers. Use a pair, becuase it depends on the protocl (only TCP/UDP have ports).
static ostream &
operator<<(ostream &os, pair<IPProto, PortNumber> pp)
{
    if (protoHasPorts(get<0>(pp))) {
        os << "|" << get<1>(pp);
    }
    return os;
}

ostream &
PendingKey::print(ostream &os) const
{
    if (getType() == IPType::UNINITIALIZED) return os << "<Uninitialized connection>";

    return os << "<" <<
        getSrc() << " -> " <<
        getDst() << make_pair(getProto(), getDPort()) <<
        " " << static_cast<uint>(getProto()) << ">";  // Cast needed to print as a number.
}

size_t
PendingKey::hash() const
{
    dbgAssert(src.type != IPType::UNINITIALIZED) << "PendingKey::hash was called on an uninitialized object";
    size_t seed = 0;
    hashCombine(seed, static_cast<u_char>(src.type));
    hashCombine(seed, src.proto);
    hashCombine(seed, src);
    hashCombine(seed, dst);
    hashCombine(seed, dst.port);
    return seed;
}
