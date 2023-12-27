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
#include "i_mainloop.h"
#include "i_encryptor.h"
#include "i_details_resolver.h"
#include "i_rest_api.h"
#include "i_time_get.h"
#include "i_shell_cmd.h"
#include "i_encryptor.h"
#include "i_env_details.h"
#include "i_declarative_policy.h"
#include "maybe_res.h"
#include "event.h"
#include "rest.h"

class ApplyPolicyEvent : public Event<ApplyPolicyEvent>
{
public:
    ApplyPolicyEvent() {}
    ApplyPolicyEvent(const std::string &path) : local_policy_path(path) {}

    // LCOV_EXCL_START Reason: no test exist
    std::string getPolicyPath() const { return local_policy_path; }
    // LCOV_EXCL_STOP

private:
    std::string local_policy_path;
};

class DeclarativePolicyUtils
        :
    public Singleton::Provide<I_DeclarativePolicy>::SelfInterface,
    public Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_LocalPolicyMgmtGen>,
    Singleton::Consume<I_EnvDetails>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_OrchestrationTools>,
    public Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_RestApi>,
    public Listener<ApplyPolicyEvent>
{
public:
    class ApplyPolicyRest : public ServerRest
    {
    public:
        void
        doCall() override
        {
            ApplyPolicyEvent(policy_path.get()).notify();
        }

    private:
        C2S_PARAM(std::string, policy_path);
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
    ) override;
    std::string getUpdate(CheckUpdateRequest &request) override;
    bool shouldApplyPolicy() override;
    void turnOffApplyPolicyFlag() override;
    void turnOnApplyPolicyFlag() override;

    std::string getCurrPolicy() override { return curr_policy; }

    void upon(const ApplyPolicyEvent &event) override;

private:
    std::string getCleanChecksum(const std::string &unclean_checksum);
    void periodicPolicyLoad();

    std::string local_policy_path;
    std::string curr_version;
    std::string curr_policy;
    std::string curr_checksum;
    bool should_apply_policy;
};

#endif // __DECLARATIVE_POLICY_UTILS_H__
