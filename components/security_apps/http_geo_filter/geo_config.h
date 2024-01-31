#ifndef __GEO_CONFIG_H__
#define __GEO_CONFIG_H__

#include <string>

#include "cereal/archives/json.hpp"
#include "debug.h"

USE_DEBUG_FLAG(D_GEO_FILTER);

class GeoFilterCountry
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            ar(cereal::make_nvp("countryName", country_name));
            ar(cereal::make_nvp("countryCode", country_code));
            ar(cereal::make_nvp("id", id));
        }  catch (const cereal::Exception &e) {
            dbgDebug(D_GEO_FILTER) << "Failed to load http geo country config, error: " << e.what();
        }
    }

    const std::string & getCountryCode() const { return country_code; }

private:
    std::string country_name;
    std::string country_code;
    std::string id;
};

class GeoConfig
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            ar(cereal::make_nvp("name", name));
            ar(cereal::make_nvp("defaultAction", default_action));
            ar(cereal::make_nvp("practiceId", id));
            ar(cereal::make_nvp("allowedCountries", allowed_countries));
            ar(cereal::make_nvp("blockedCountries", blocked_countries));
        } catch (const cereal::Exception &e) {
            dbgDebug(D_GEO_FILTER) << "Failed to load http geo config, error: " << e.what();
        }
    }

    const std::string & getId() const { return id; }
    const std::string & getDefaultAction() const { return default_action; }

    bool
    isAllowedCountry(const std::string &_country_code) const
    {
        dbgTrace(D_GEO_FILTER) << "Check if country code: " << _country_code << " is allowed";
        for (const GeoFilterCountry &country : allowed_countries) {
            if (country.getCountryCode() == _country_code) {
                dbgTrace(D_GEO_FILTER) << "County code: " << _country_code << " is allowed";
                return true;
            }
        }
        dbgTrace(D_GEO_FILTER) << "County code: " << _country_code << " not in allowed countries list";
        return false;
    }

    bool
    isBlockedCountry(const std::string &_country_code) const
    {
        dbgTrace(D_GEO_FILTER) << "Check if country code: " << _country_code << " is blocked";
        for (const GeoFilterCountry &country : blocked_countries) {
            if (country.getCountryCode() == _country_code) {
                dbgTrace(D_GEO_FILTER) << "County code: " << _country_code << " is blocked";
                return true;
            }
        }
        dbgTrace(D_GEO_FILTER) << "County code: " << _country_code << " not in blocked countries list";
        return false;
    }

private:
    std::string name;
    std::string default_action;
    std::string id;
    std::vector<GeoFilterCountry> allowed_countries;
    std::vector<GeoFilterCountry> blocked_countries;
};

#endif //__GEO_CONFIG_H__
