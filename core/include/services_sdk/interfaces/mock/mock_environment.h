#ifndef __MOCK_ENVIRONMENT_H__
#define __MOCK_ENVIRONMENT_H__

#include "i_environment.h"
#include "singleton.h"
#include "cptest.h"

std::ostream &
operator<<(std::ostream &os, const Maybe<std::string, Context::Error> &)
{
    return os;
}

class MockEnvironment : public Singleton::Provide<I_Environment>::From<MockProvider<I_Environment>>
{
public:
    MOCK_METHOD0      (getConfigurationContext,     Context &());
    MOCK_CONST_METHOD0(getActiveContexts,           const ActiveContexts &());

    MOCK_METHOD2      (setActiveTenantAndProfile,   void(const std::string &, const std::string &));
    MOCK_METHOD0      (unsetActiveTenantAndProfile, void());

    MOCK_METHOD1      (registerContext,             void(Context *));
    MOCK_METHOD1      (unregisterContext,           void(Context *));

    MOCK_METHOD0      (createEnvironment,           ActiveContexts());
    MOCK_METHOD0      (saveEnvironment,             ActiveContexts());

    MOCK_CONST_METHOD0(getCurrentTrace,             std::string());
    MOCK_CONST_METHOD0(getCurrentSpan,              std::string());
    MOCK_METHOD0(getCurrentHeaders,                 std::string());
    MOCK_METHOD2(startNewTrace,                     void(bool, const std::string &));
    MOCK_METHOD3(startNewSpan,                      void(Span::ContextType, const std::string &, const std::string &));

    using on_exit = std::scope_exit<std::function<void(void)>>;
    MOCK_METHOD3(startNewSpanScope,                 on_exit(Span::ContextType,
                                                    const std::string &, const std::string &));
    MOCK_METHOD1(finishTrace,                       void(const std::string &));
    MOCK_METHOD1(finishSpan,                        void(const std::string &));

    // You can't mock a function with an R-value reference. So mock a slightly different one
    void loadEnvironment(ActiveContexts &&env) { mockLoadEnvironment(env); }
    MOCK_METHOD1      (mockLoadEnvironment,     void(const ActiveContexts &));

    MOCK_CONST_METHOD1(getAllStrings,               std::map<std::string, std::string>(const EnvKeyAttr::ParamAttr &));
    MOCK_CONST_METHOD1(getAllUints,                 std::map<std::string, uint64_t>(const EnvKeyAttr::ParamAttr &));
    MOCK_CONST_METHOD1(getAllBools,                 std::map<std::string, bool>(const EnvKeyAttr::ParamAttr &));
};

#endif // __MOCK_ENVIRONMENT_H__
