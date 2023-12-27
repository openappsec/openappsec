#ifndef __I_DECLARATIVE_POLICY__
#define __I_DECLARATIVE_POLICY__

#include <string>

#include "singleton.h"
#include "orchestrator/rest_api/orchestration_check_update.h"

class I_DeclarativePolicy
{
public:
    virtual bool shouldApplyPolicy() = 0;

    virtual std::string getUpdate(CheckUpdateRequest &request) = 0;

    virtual void sendUpdatesToFog(
        const std::string &access_token,
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &fog_address
    ) = 0;

    virtual std::string getCurrPolicy() = 0;

    virtual void turnOffApplyPolicyFlag() = 0;
    virtual void turnOnApplyPolicyFlag() = 0;

protected:
    virtual ~I_DeclarativePolicy() {}
};


#endif // __I_DECLARATIVE_POLICY__
