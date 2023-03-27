#ifndef __DECLARATIVE_POLICY_UTILS_H__
#define __DECLARATIVE_POLICY_UTILS_H__

#include <chrono>
#include <functional>
#include <tuple>
#include <vector>
#include "cereal/archives/json.hpp"

#include "singleton.h"
#include "i_update_communication.h"
#include "fog_authenticator.h"
#include "i_local_policy_mgmt_gen.h"
#include "i_orchestration_tools.h"
#include "i_agent_details.h"
#include "i_orchestration_status.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_encryptor.h"
#include "i_details_resolver.h"
#include "i_rest_api.h"
#include "i_time_get.h"
#include "i_shell_cmd.h"
#include "i_encryptor.h"
#include "i_env_details.h"
#include "maybe_res.h"
#include "event.h"

class ApplyPolicyEvent : public Event<ApplyPolicyEvent>
{
public:
    ApplyPolicyEvent() {}
};

class DeclarativePolicyUtils
        :
    public Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_LocalPolicyMgmtGen>,
    Singleton::Consume<I_EnvDetails>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_RestApi>,
    public Listener<ApplyPolicyEvent>
{
public:
    class ApplyPolicyRest : public ServerRest
    {
    public:
        // LCOV_EXCL_START Reason: no test exist
        void
        doCall() override
        {
            ApplyPolicyEvent().notify();
        }
        // LCOV_EXCL_STOP
    };

    void init();
    Maybe<std::string> getLocalPolicyChecksum();
    std::string getPolicyChecksum();
    void updateCurrentPolicy(const std::string &policy_checksum);
    void sendUpdatesToFog(
        const std::string &access_token,
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &fog_address
    );
    std::string getUpdate(CheckUpdateRequest &request);
    bool shouldApplyPolicy();
    void turnOffApplyPolicyFlag();

    std::string getCurrVersion() { return curr_version; }
    std::string getCurrPolicy() { return curr_policy; }

    void upon(const ApplyPolicyEvent &event) override;

private:
    std::string getCleanChecksum(const std::string &unclean_checksum);

    std::string curr_version;
    std::string curr_policy;
    bool should_apply_policy;
};

#endif // __DECLARATIVE_POLICY_UTILS_H__
