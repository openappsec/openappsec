#ifndef __BYTEORDER_H__
#define __BYTEORDER_H__

// Byte Order (Net-to-Host, Host-to-Net) operations
//
// C provides htons, ntohs, htonl, ntohl, but they're not "constexpr" so are unusable in case labels.
// C++ proposal N3620 adds some function, but it's not accepted (yet?). It uses templates which are,
//  IMO, a bit complicated so I chose not to adapt it.

static inline constexpr uint16_t
constHTONS(uint16_t h_ord)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((h_ord>>8) & 0xff) |
        ((h_ord&0xff) << 8);
#elif __BYTE_ORDER == __BIG_ENDIAN
    return h_ord;
#else
#error unknown byte order
#endif // __BYTE_ORDER
}

static inline constexpr uint16_t
constNTOHS(uint16_t n_ord)
{
    return constHTONS(n_ord);    // Same thing
}

static inline constexpr uint32_t
constHTONL(uint32_t h_ord)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((constHTONS(h_ord>>16)) & 0xffff) |
        ((constHTONS(h_ord&0xffff)) << 16);
#elif __BYTE_ORDER == __BIG_ENDIAN
    return h_ord;
#else
#error unknown byte order
#endif // __BYTE_ORDER
}

static inline constexpr uint32_t
constNTOHL(uint32_t n_ord)
{
    return constHTONL(n_ord);    // Same thing
}

#endif // __BYTEORDER_H__
