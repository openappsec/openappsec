#ifndef __GEO_LOCATION_H__
#define __GEO_LOCATION_H__

#include "i_geo_location.h"
#include "singleton.h"
#include "component.h"

class GeoLocation : public Component, Singleton::Provide<I_GeoLocation>
{
public:
    GeoLocation();
    ~GeoLocation();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __GEO_LOCATION_H__
