#include "RequestsMonitor.h"
#include "waap.h"
#include "SyncLearningNotification.h"
#include "report_messaging.h"
#include "customized_cereal_map.h"

USE_DEBUG_FLAG(D_WAAP_CONFIDENCE_CALCULATOR);
using namespace std;

SourcesRequestMonitor::SourcesRequestMonitor(
    const string& filePath,
    const string& remotePath,
    const string& assetId,
    const string& owner) :
    SerializeToLocalAndRemoteSyncBase(
        chrono::minutes(10),
        chrono::seconds(30),
        filePath,
        remotePath != "" ? remotePath + "/Monitor" : remotePath,
        assetId,
        owner
    ), m_sourcesRequests()
{
}

SourcesRequestMonitor::~SourcesRequestMonitor()
{
}

void SourcesRequestMonitor::syncWorker()
{
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Running the sync worker for assetId='" << m_assetId << "', owner='" <<
        m_owner << "'";
    incrementIntervalsCount();
    OrchestrationMode mode = Singleton::exists<I_AgentDetails>() ?
        Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getOrchestrationMode() : OrchestrationMode::ONLINE;

    bool enabled = getProfileAgentSettingWithDefault<bool>(false, "appsec.sourceRequestsMonitor.enabled");

    if (mode == OrchestrationMode::OFFLINE || !enabled || isBase() || !postData()) {
        dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR)
            << "Did not report data. for asset: "
            << m_assetId
            << " Remote URL: "
            << m_remotePath
            << " is enabled: "
            << to_string(enabled)
            << ", mode: " << int(mode);
        return;
    }

    dbgTrace(D_WAAP_CONFIDENCE_CALCULATOR) << "Waiting for all agents to post their data";
    waitSync();

    if (mode == OrchestrationMode::HYBRID) {
        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "detected running in standalone mode. not sending sync notification";
    } else {
        SyncLearningNotificationObject syncNotification(m_assetId, "Monitor", getWindowId());

        dbgDebug(D_WAAP_CONFIDENCE_CALCULATOR) << "sending sync notification: " << syncNotification;

        ReportMessaging(
            "sync notification for '" + m_assetId + "'",
            ReportIS::AudienceTeam::WAAP,
            syncNotification,
            MessageCategory::GENERIC,
            ReportIS::Tags::WAF,
            ReportIS::Notification::SYNC_LEARNING
        );
    }
}

void SourcesRequestMonitor::logSourceHit(const string& source)
{
    m_sourcesRequests[chrono::duration_cast<chrono::minutes>(
        Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime()
    ).count()][source]++;
}

// LCOV_EXCL_START Reason: internal functions not used

void SourcesRequestMonitor::pullData(const vector<string> &data)
{
    // not used. report only
}

void SourcesRequestMonitor::processData()
{
    // not used. report only
}

void SourcesRequestMonitor::postProcessedData()
{
    // not used. report only
}

void SourcesRequestMonitor::pullProcessedData(const vector<string> &data)
{
    // not used. report only
}

void SourcesRequestMonitor::updateState(const vector<string> &data)
{
    // not used. report only
}

// LCOV_EXCL_STOP

typedef map<string, map<string, size_t>> MonitorJsonData;

class SourcesRequestsReport : public RestGetFile
{
public:
    SourcesRequestsReport(MonitorData& _sourcesRequests, const string& _agentId)
        : sourcesRequests(), agentId(_agentId)
    {
        MonitorJsonData montiorData;
        for (const auto& window : _sourcesRequests) {
            for (const auto& source : window.second) {
                montiorData[to_string(window.first)][source.first] = source.second;
            }
        }
        sourcesRequests = montiorData;
    }
    private:
    C2S_PARAM(MonitorJsonData, sourcesRequests);
    C2S_PARAM(string, agentId);
};

bool SourcesRequestMonitor::postData()
{
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Sending the data to remote";
    // send collected data to remote and clear the local data
    string url = getPostDataUrl();
    string agentId = Singleton::Consume<I_AgentDetails>::by<WaapComponent>()->getAgentId();
    SourcesRequestsReport currentWindow(m_sourcesRequests, agentId);
    bool ok = sendNoReplyObjectWithRetry(currentWindow,
        HTTPMethod::PUT,
        url);
    if (!ok) {
        dbgError(D_WAAP_CONFIDENCE_CALCULATOR) << "Failed to post collected data to: " << url;
    }
    dbgInfo(D_WAAP_CONFIDENCE_CALCULATOR) << "Data sent to remote: " << ok;
    m_sourcesRequests.clear();
    return ok;
}

void SourcesRequestMonitor::serialize(ostream& stream)
{
    cereal::JSONOutputArchive archive(stream);
    archive(m_sourcesRequests);
}

void SourcesRequestMonitor::deserialize(istream& stream)
{
    cereal::JSONInputArchive archive(stream);
    archive(m_sourcesRequests);
}
