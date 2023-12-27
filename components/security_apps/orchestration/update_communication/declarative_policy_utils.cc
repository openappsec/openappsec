#include "declarative_policy_utils.h"

#include "config.h"
#include "log_generator.h"
#include "agent_details.h"
#include "version.h"

#include <algorithm>
#include <map>
#include <vector>

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
DeclarativePolicyUtils::init()
{
    local_policy_path = getFilesystemPathConfig() + "/conf/local_policy.yaml";
    should_apply_policy = true;
    Singleton::Consume<I_RestApi>::by<DeclarativePolicyUtils>()->addRestCall<ApplyPolicyRest>(
        RestAction::SET, "apply-policy"
    );
    registerListener();
    char *automatic_load = getenv("autoPolicyLoad");
    if (automatic_load != nullptr && automatic_load == string("true")) {
        auto mainloop = Singleton::Consume<I_MainLoop>::by<DeclarativePolicyUtils>();
        mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::Offline,
            chrono::seconds(30),
            [&] () { periodicPolicyLoad(); },
            "Automatic Policy Loading"
        );
    }
}

// LCOV_EXCL_START Reason: no test exist
void
DeclarativePolicyUtils::upon(const ApplyPolicyEvent &event)
{
    dbgTrace(D_ORCHESTRATOR) << "Apply policy event";
    local_policy_path = event.getPolicyPath();
    should_apply_policy = true;
}
// LCOV_EXCL_STOP

bool
DeclarativePolicyUtils::shouldApplyPolicy()
{
    auto env_type = Singleton::Consume<I_EnvDetails>::by<DeclarativePolicyUtils>()->getEnvType();
    return env_type == EnvType::K8S ? true : should_apply_policy;
}

void
DeclarativePolicyUtils::turnOffApplyPolicyFlag()
{
    should_apply_policy = false;
}

void
DeclarativePolicyUtils::turnOnApplyPolicyFlag()
{
    should_apply_policy = true;
}

Maybe<string>
DeclarativePolicyUtils::getLocalPolicyChecksum()
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<DeclarativePolicyUtils>();
    auto env_type = Singleton::Consume<I_EnvDetails>::by<DeclarativePolicyUtils>()->getEnvType();
    if (env_type == EnvType::K8S) {
        return orchestration_tools->readFile("/etc/cp/conf/k8s-policy-check.trigger");
    }

    Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        local_policy_path
    );

    if (!file_checksum.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Policy checksum was not calculated: " << file_checksum.getErr();
        return genError(file_checksum.getErr());
    }

    return file_checksum.unpack();
}

string
DeclarativePolicyUtils::getCleanChecksum(const string &unclean_checksum)
{
    string clean_checksum = unclean_checksum;
    if (!clean_checksum.empty() && clean_checksum[clean_checksum.size() - 1] == '\n') {
        clean_checksum.erase(clean_checksum.size() - 1);
    }
    return clean_checksum;
}

void
DeclarativePolicyUtils::updateCurrentPolicy(const string &policy_checksum)
{
    string clean_policy_checksum = getCleanChecksum(policy_checksum);
    auto env = Singleton::Consume<I_EnvDetails>::by<DeclarativePolicyUtils>()->getEnvType();
    curr_policy = Singleton::Consume<I_LocalPolicyMgmtGen>::by<DeclarativePolicyUtils>()->generateAppSecLocalPolicy(
        env,
        clean_policy_checksum,
        local_policy_path
    );
}

string
DeclarativePolicyUtils::getPolicyChecksum()
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<DeclarativePolicyUtils>();
    Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        "/tmp/local_appsec.policy"
    );

    if (!file_checksum.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed policy checksum calculation";
        return "";
    }
    return file_checksum.unpack();
}

void
DeclarativePolicyUtils::sendUpdatesToFog(
    const string &access_token,
    const string &tenant_id,
    const string &profile_id,
    const string &fog_address)
{
    auto shell_cmd = Singleton::Consume<I_ShellCmd>::by<DeclarativePolicyUtils>();
    string exec_command =
        getFilesystemPathConfig()
        + "/scripts/open-appsec-cloud-mgmt --upload_policy_only"
        + " --access_token " + access_token
        + " --tenant_id " + tenant_id
        + " --profile_id " + profile_id;
    auto env = Singleton::Consume<I_EnvDetails>::by<DeclarativePolicyUtils>()->getEnvType();
    if (env == EnvType::K8S) {
        exec_command =
            getFilesystemPathConfig()
            + "/scripts/open-appsec-cloud-mgmt-k8s"
            + " --access_token " + access_token;
    }
    if (fog_address != "") exec_command = exec_command + " --fog https://" + fog_address;

    auto maybe_cmd_output = shell_cmd->getExecOutput(
        exec_command,
        300000,
        false
    );
    if (maybe_cmd_output.ok()) {
        dbgTrace(D_ORCHESTRATOR) << "Successfully send policy updates to the fog";
    } else {
        dbgError(D_ORCHESTRATOR) << "Failed to send policy updates to the fog. Error: " << maybe_cmd_output.getErr();
    }
}

string
DeclarativePolicyUtils::getUpdate(CheckUpdateRequest &request)
{
    dbgTrace(D_ORCHESTRATOR) << "Getting policy update in declarative policy";

    string policy_response = "";
    auto policy_checksum = request.getPolicy();

    auto maybe_new_version = getLocalPolicyChecksum();
    if (!maybe_new_version.ok() || maybe_new_version == curr_version) {
        dbgDebug(D_ORCHESTRATOR) << "No new version is currently available";
        return "";
    }

    updateCurrentPolicy(maybe_new_version.unpack());
    string offline_policy_checksum = getPolicyChecksum();
    if (!policy_checksum.ok() || offline_policy_checksum != policy_checksum.unpack()) {
        dbgTrace(D_ORCHESTRATOR) << "Update policy checksum";
        policy_response = offline_policy_checksum;
    }

    dbgDebug(D_ORCHESTRATOR)
        << "Local update response, "
        << "policy: "
        << (policy_response.empty() ? "has no change," : "has new update," );
    curr_version = maybe_new_version.unpack();
    return policy_response;
}

void
DeclarativePolicyUtils::periodicPolicyLoad()
{
    auto new_checksum = getLocalPolicyChecksum();

    if (!new_checksum.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to calculate checksum";
        return;
    }

    if (*new_checksum == curr_checksum) return;

    should_apply_policy = true;
    curr_checksum = *new_checksum;
}
