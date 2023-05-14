#ifndef __IPS_ENUMS_H__
#define __IPS_ENUMS_H__

namespace IPSSignatureSubTypes
{

enum class SignatureAction
{
    PREVENT,
    DETECT,
    IGNORE
};

enum class IPSLevel
{
    VERY_LOW,
    LOW,
    MEDIUM_LOW,
    MEDIUM,
    MEDIUM_HIGH,
    HIGH,
    CRITICAL
};

}  // IPSSignatureSubTypes
#endif // __IPS_ENUMS_H__
