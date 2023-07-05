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
    MOCK_CONST_METHOD0(fetchActiveTenantsAndProfiles,     std::map<std::string, std::set<std::string>>());
    MOCK_CONST_METHOD0(fetchActiveTenants,          std::set<std::string>());
    MOCK_CONST_METHOD0(fetchAllActiveTenants,       std::set<std::string>());
    MOCK_CONST_METHOD1(fetchProfileIds,             std::set<std::string>(const std::string &));
    MOCK_CONST_METHOD2(
        getInstances,
        std::set<std::string>(const std::string &, const std::string &)
    );
    MOCK_CONST_METHOD2(areTenantAndProfileActive,   bool(const std::string &, const std::string &));
    MOCK_METHOD2(addActiveTenantAndProfile,         void(const std::string &, const std::string &));
    MOCK_METHOD2(deactivateTenant,                  void(const std::string &, const std::string &));
    MOCK_METHOD1(fetchAndUpdateActiveTenantsAndProfiles, std::map<std::string, std::set<std::string>>(bool));
    MOCK_CONST_METHOD3(
        getProfileIdsForRegionAccount,
        std::set<std::string>(const std::string &, const std::string &, const std::string &)
    );
private:
    MOCK_METHOD3(
        addInstance,
        void(const std::string &, const std::string &, const std::string &)
    );
};

#endif // __MOCK_TENANT_MANAGER_H__
