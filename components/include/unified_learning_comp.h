#ifndef __UNIFIED_LEARNING_COMP_H__
#define __UNIFIED_LEARNING_COMP_H__

#include <memory>
#include "component.h"
#include "i_mainloop.h"
#include "i_socket_is.h"
#include "i_unified_learning.h"
#include "singleton.h"

class UnifiedLearningComponent :
    public Component,
    public Singleton::Provide<I_UnifiedLearning>,
    public Singleton::Consume<I_MainLoop>,
    public Singleton::Consume<I_Socket>,
    public Singleton::Consume<I_TimeGet>,
    public Singleton::Consume<I_Messaging>,
    public Singleton::Consume<I_AgentDetails>,
    public Singleton::Consume<I_InstanceAwareness>,
    public Singleton::Consume<I_Encryptor>

{
public:
    UnifiedLearningComponent();
    ~UnifiedLearningComponent();

    void preload() override;
    void init() override;
    void fini() override;
    

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __UNIFIED_LEARNING_COMP_H__
