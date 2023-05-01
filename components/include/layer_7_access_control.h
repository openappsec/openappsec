#ifndef __LAYER_7_ACCESS_CONTROL_H__
#define __LAYER_7_ACCESS_CONTROL_H__

#include <memory>

#include "singleton.h"
#include "i_mainloop.h"
#include "component.h"
#include "i_intelligence_is_v2.h"

#include <string>

class Layer7AccessControl
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Intelligence_IS_V2>,
    Singleton::Consume<I_Environment>
{
public:
    Layer7AccessControl();
    ~Layer7AccessControl();

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __LAYER_7_ACCESS_CONTROL_H__
