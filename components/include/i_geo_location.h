#ifndef __I_GEO_LOCATION_H__
#define __I_GEO_LOCATION_H__

#include <string>

#include "connkey.h"
#include "enum_array.h"


class I_GeoLocation
{
public:
    enum class GeoLocationField { COUNTRY_NAME, COUNTRY_CODE, CONTINENT_NAME, CONTINENT_CODE, COUNT };

    virtual Maybe<EnumArray<GeoLocationField, std::string>> lookupLocation(const std::string &ip) = 0;
    virtual Maybe<EnumArray<GeoLocationField, std::string>> lookupLocation(const IPAddr &ip) = 0;

protected:
    virtual ~I_GeoLocation() {}
};

#endif // __I_GEO_LOCATION_H__
