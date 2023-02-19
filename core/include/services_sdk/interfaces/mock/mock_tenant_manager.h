#ifndef __MOCK_TENANT_MANAGER_H__
#define __MOCK_TENANT_MANAGER_H__

#include "i_tenant_manager.h"

#include <string>
#include <vector>
#include <chrono>

#include "singleton.h"
#include "cptest.h"

class MockTenantManager : public Singleton::Provide<I_TenantManager>::From<MockProvider<I_TenantManager>>
{
public:
    MOCK_METHOD1(uponNewTenants,                    void(const I_TenantManager::newTenantCB &cb));

    MOCK_CONST_METHOD0(fetchActiveTenants,          std::vector<std::string>());
    MOCK_CONST_METHOD0(fetchAllActiveTenants,       std::vector<std::string>());
    MOCK_CONST_METHOD1(fetchProfileIds,             std::vector<std::string>(const std::string &));
    MOCK_CONST_METHOD2(
        getInstances,
        std::vector<std::string>(const std::string &, const std::string &)
    );
    MOCK_CONST_METHOD2(areTenantAndProfileActive,   bool(const std::string &, const std::string &));
    MOCK_METHOD2(addActiveTenantAndProfile,         void(const std::string &, const std::string &));
    MOCK_METHOD2(deactivateTenant,                  void(const std::string &, const std::string &));
    MOCK_CONST_METHOD2(getProfileId,                std::string(const std::string &, const std::string &));

    MOCK_CONST_METHOD0(getTimeoutVal,               std::chrono::microseconds());

private:
    MOCK_METHOD3(
        addInstance,
        void(const std::string &, const std::string &, const std::string &)
    );
};

#endif // __MOCK_TENANT_MANAGER_H__
