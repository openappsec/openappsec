#include "snort_section.h"

using namespace std;

USE_DEBUG_FLAG(D_K8S_POLICY);
// LCOV_EXCL_START Reason: no test exist

AgentSettingsSection::AgentSettingsSection(string _key, string _value) : key(_key), value(_value)
{
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_K8S_POLICY) << "Failed to generate agent setting UUID. Error: " << e.what();
    }
}

void
AgentSettingsSection::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("id",    id),
        cereal::make_nvp("key",   key),
        cereal::make_nvp("value", value)
    );
}

void
IpsSnortSigsRulebase::save(cereal::JSONOutputArchive &out_ar) const
{
    string profile_type = "KubernetesProfile";
    string upgrade_mode = "automatic";
    out_ar(
        cereal::make_nvp("agentSettings",                agentSettings),
        cereal::make_nvp("agentType",                    profile_type),
        cereal::make_nvp("allowOnlyDefinedApplications", false),
        cereal::make_nvp("anyFog",                       true),
        cereal::make_nvp("maxNumberOfAgents",            10),
        cereal::make_nvp("upgradeMode",                  upgrade_mode)
    );
}
// LCOV_EXCL_STOP
