#ifndef __PENDING_KEY_H__
#define __PENDING_KEY_H__

#include <netinet/in.h>
#include <tuple>
#include <string.h>
#include "debug.h"
#include "maybe_res.h"
#include "connkey.h"

class PendingKey
{
public:
    explicit PendingKey() {}
    explicit PendingKey(
        const IPAddr &_src,
        const IPAddr &_dst,
        PortNumber dport,
        IPProto proto)
            :
        src(_src),
        dst(_dst)
    {
        dst.port = dport;
        src.proto = proto;
        dst.proto = proto;
    }

    PendingKey(const ConnKey &key) : PendingKey(key.getSrc(), key.getDst(), key.getDPort(), key.getProto()) {}

    bool
    operator==(const PendingKey &other) const
    {
        auto my_tuple = std::tie(src, dst, dst.port, src.proto);
        auto other_tuple = std::tie(other.src, other.dst, other.dst.port, other.src.proto);
        return my_tuple == other_tuple;
    }

    bool
    operator!=(const PendingKey &other) const
    {
        return !(*this == other);
    }

    const IPAddr & getSrc() const { return src; }
    const IPAddr & getDst() const { return dst; }
    PortNumber getDPort() const { return dst.port; }
    IPProto getProto() const { return src.proto; }

    Maybe<IPType>
    getType() const
    {
        if(src.type != dst.type) return genError("Mismatch in connection types (Src and Dst types are not identical)");
        return src.type;
    }

    std::ostream & print(std::ostream &os) const;
    size_t hash() const;

    template<class Archive>
    void
    serialize(Archive &ar, uint32_t)
    {
        ar(src, dst);
    }

private:
    IPAddr src, dst;
};

// Specialization of std::hash<> for ConnKey
namespace std
{

template <>
struct hash<PendingKey>
{
    size_t operator()(const PendingKey &k) const { return k.hash(); }
};

} // namespace std

static inline std::ostream & operator<<(std::ostream &os, const PendingKey &k) { return k.print(os); }

#endif // __PENDING_KEY_H__
