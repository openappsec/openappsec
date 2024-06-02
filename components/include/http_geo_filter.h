#ifndef __HTTP_GEO_FILTER_H__
#define __HTTP_GEO_FILTER_H__

#include <memory>

#include "singleton.h"
#include "i_mainloop.h"
#include "component.h"
#include "http_inspection_events.h"
#include "i_geo_location.h"
#include "i_generic_rulebase.h"

class HttpGeoFilter
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_GeoLocation>,
    Singleton::Consume<I_GenericRulebase>,
    Singleton::Consume<I_Environment>
{
public:
    HttpGeoFilter();
    ~HttpGeoFilter();

    void preload() override;

    void init() override;
    void fini() override;


private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __HTTP_GEO_FILTER_H__
