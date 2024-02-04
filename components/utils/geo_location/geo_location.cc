#include "geo_location.h"

#include <maxminddb.h>

#include "config.h"
#include "debug.h"
#include "enum_range.h"

using namespace std;

USE_DEBUG_FLAG(D_GEO_DB);

class GeoLocation::Impl : Singleton::Provide<I_GeoLocation>::From<GeoLocation>
{
public:
    void
    preload()
    {
        registerExpectedConfigFile("agentGeoDb", Config::ConfigFileType::RawData);
    }

    void
    init()
    {
        registerConfigLoadCb([this]() { initGeoDbObj(); });
        initGeoDbObj();
    }

    void
    fini()
    {
        if (mind_db_obj_status != MMDB_SUCCESS) return;
        MMDB_close(&max_mind_db_obj);
        dbgTrace(D_GEO_DB) << "Closed geo location DB";
    }

    Maybe<EnumArray<I_GeoLocation::GeoLocationField, string>>
    lookupLocation(const string &ip) override
    {
        dbgFlow(D_GEO_DB) << "Geo location lookup by string";

        if (mind_db_obj_status != MMDB_SUCCESS) {
            dbgDebug(D_GEO_DB) << "Maxmind db is uninitialized";
            return genError("Maxmind db is uninitialized");
        }

        Maybe<IPAddr> maybe_ip_addr = IPAddr::createIPAddr(ip);

        if (!maybe_ip_addr.ok()) {
            dbgWarning(D_GEO_DB)
                << "Error in creating IPAddr from string: "
                << ip
                << ", error: "
                << maybe_ip_addr.getErr();
            return genError(
                "Error in creating IPAddr from string: " +
                ip +
                ", error: " +
                maybe_ip_addr.getErr()
            );
        }

        return lookupLocation(maybe_ip_addr.unpack());
    }

    Maybe<EnumArray<I_GeoLocation::GeoLocationField, string>>
    lookupLocation(const IPAddr &ip) override
    {
        dbgFlow(D_GEO_DB) << "Geo location lookup by IPAddr";

        if (mind_db_obj_status != MMDB_SUCCESS) {
            dbgDebug(D_GEO_DB) << "Maxmind db is uninitialized";
            return genError("Maxmind db is uninitialized");
        }

        int maxminddb_error;
        struct sockaddr sockaddr_to_search = convertIPAddrtoSockaddr(ip);

        MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&max_mind_db_obj, &sockaddr_to_search, &maxminddb_error);
        if (maxminddb_error != MMDB_SUCCESS) {
            dbgWarning(D_GEO_DB) << "maxMindDB error: " << MMDB_strerror(maxminddb_error);
            return genError("maxMindDB error: " + string(MMDB_strerror(maxminddb_error)));
        }
        if (result.found_entry) {
            return getGeoLocationDetails(result);
        }
        return genError("No results were found by lookup geo location");
    }

private:
    void
    initGeoDbObj()
    {
        if (mind_db_obj_status == MMDB_SUCCESS) {
            dbgTrace(D_GEO_DB) << "Closing an open geo location DB file";
            MMDB_close(&max_mind_db_obj);
            mind_db_obj_status = -1;
        }

        string geo_location_db_file = getPolicyConfigPath("agentGeoDb", Config::ConfigFileType::RawData);
        dbgDebug(D_GEO_DB) << "Path to GeoDb file" << geo_location_db_file;
        if (geo_location_db_file == "") {
            dbgWarning(D_GEO_DB) << "No geo location db file specified";
            return;
        }

        mind_db_obj_status = MMDB_open(geo_location_db_file.c_str(), MMDB_MODE_MMAP, &max_mind_db_obj);
        if (mind_db_obj_status != MMDB_SUCCESS) {
            dbgWarning(D_GEO_DB) << "maxMindDB error: " << MMDB_strerror(mind_db_obj_status);
            if (mind_db_obj_status == MMDB_IO_ERROR) {
                dbgWarning(D_GEO_DB) << "maxMindDB IO error: " << strerror(mind_db_obj_status);
            }
            return;
        }
        dbgDebug(D_GEO_DB) << "Successfully Opened geo location DB";
    }

    EnumArray<I_GeoLocation::GeoLocationField, string>
    getGeoLocationDetails(MMDB_lookup_result_s &result)
    {
        EnumArray<I_GeoLocation::GeoLocationField, string> geo_location_details;
        for (I_GeoLocation::GeoLocationField geo_field : makeRange<I_GeoLocation::GeoLocationField>()) {
            geo_location_details[geo_field] = getGeoLocationValueResults(result, geo_field);
        }
        return geo_location_details;
    }

    string
    getGeoLocationValueResults(MMDB_lookup_result_s &result, I_GeoLocation::GeoLocationField field_type)
    {
        MMDB_entry_data_s entry_data;
        int status = -1;
        switch (field_type) {
            case I_GeoLocation::GeoLocationField::COUNTRY_NAME: {
                status = MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL);
                break;
            }
            case I_GeoLocation::GeoLocationField::COUNTRY_CODE: {
                status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
                break;
            }
            case I_GeoLocation::GeoLocationField::CONTINENT_NAME: {
                status = MMDB_get_value(&result.entry, &entry_data, "continent", "names", "en", NULL);
                break;
            }
            case I_GeoLocation::GeoLocationField::CONTINENT_CODE: {
                status = MMDB_get_value(&result.entry, &entry_data, "continent", "code", NULL);
                break;
            }
            default: {
                dbgError(D_GEO_DB) << "Invalid geo location field type";
                break;
            }
        }
        if (status != MMDB_SUCCESS) {
            dbgWarning(D_GEO_DB) << "maxMindDB error: " << MMDB_strerror(status);
        } else if (!entry_data.has_data) {
            dbgWarning(D_GEO_DB) << "maxMindDB Entry has no data";
        } else {
            string search_result(entry_data.utf8_string, entry_data.data_size);
            return search_result;
        }
        return "";
    }

    struct sockaddr
    convertIPAddrtoSockaddr(const IPAddr &address)
    {
        if (address.getType() == IPType::V6) {
            struct sockaddr_in6 sa6;
            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr = address.getIPv6();
            return *(struct sockaddr *)&sa6;
        }

        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        sa.sin_addr = address.getIPv4();
        return *(struct sockaddr *)&sa;
    }

    MMDB_s max_mind_db_obj;
    int mind_db_obj_status = -1;
};

GeoLocation::GeoLocation() : Component("GeoLocation"), pimpl(make_unique<Impl>()) {}

GeoLocation::~GeoLocation() {}

void GeoLocation::preload() { pimpl->preload(); }

void GeoLocation::init() { pimpl->init(); }

void GeoLocation::fini() { pimpl->fini(); }
