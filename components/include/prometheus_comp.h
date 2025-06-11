#ifndef __PROMETHEUS_COMP_H__
#define __PROMETHEUS_COMP_H__

#include <memory>

#include "component.h"
#include "singleton.h"

#include "i_rest_api.h"
#include "i_messaging.h"
#include "generic_metric.h"

class PrometheusComp
        :
    public Component,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_Messaging>
{
public:
    PrometheusComp();
    ~PrometheusComp();

    void init() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __PROMETHEUS_COMP_H__
