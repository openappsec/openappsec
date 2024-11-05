// Copyright (C) 2024 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "WaapModelResultLogger.h"
#include "Waf2Engine.h"
#include "i_time_get.h"
#include "i_messaging.h"
#include "i_instance_awareness.h"
#include "http_manager.h"
#include "LogGenWrapper.h"
#include "rest.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_MODEL_LOGGER);

using namespace std;

static const unsigned int MAX_FILES_PER_WINDOW = 5;
static const unsigned int MAX_LOGS_PER_WINDOW = 1800;
static constexpr std::chrono::minutes RATE_LIMIT_WINDOW_MINUTES = std::chrono::minutes(30);

class WaapModelReport : public RestGetFile
{
public:
    WaapModelReport(const vector<WaapModelResult> &_data) : data(_data) {}

private:
    C2S_PARAM(vector<WaapModelResult>, data);
};

class WaapModelResultLogger::Impl
        :
    Singleton::Provide<I_WaapModelResultLogger>::From<WaapModelResultLogger>
{
public:
    Impl(size_t maxLogs) : max_logs(maxLogs), sent_files_count(0), sent_logs_count(0),
        last_sent_s3(std::chrono::minutes::zero()),
        last_kusto_log_window(std::chrono::minutes::zero()) {}
    virtual ~Impl();
    void
    logModelResult(
        Waap::Scores::ModelLoggingSettings &settings,
        IWaf2Transaction* transaction,
        Waf2ScanResult &res,
        string modelName,
        string otherModelName,
        double score,
        double otherScore) override;

private:
    void logToStream(WaapModelResult &result, chrono::minutes now);
    void logToS3(WaapModelResult &result, IWaf2Transaction* transaction, chrono::minutes now);
    bool shouldSendLogsToS3(chrono::minutes now);
    void sendLogsToS3();
    size_t max_logs;
    unsigned int sent_files_count;
    unsigned int sent_logs_count;
    std::chrono::minutes last_sent_s3;
    std::chrono::minutes last_kusto_log_window;
    std::map<std::string, vector<WaapModelResult>> logs;
};

WaapModelResultLogger::WaapModelResultLogger(size_t maxLogs) : pimpl(make_unique<WaapModelResultLogger::Impl>(maxLogs))
{
}

WaapModelResultLogger::~WaapModelResultLogger()
{
}

void
WaapModelResultLogger::logModelResult(
    Waap::Scores::ModelLoggingSettings &settings,
    IWaf2Transaction* transaction,
    Waf2ScanResult &res,
    std::string modelName,
    std::string otherModelName,
    double score,
    double otherScore
)
{
    pimpl->logModelResult(settings, transaction, res, modelName, otherModelName, score, otherScore);
}

void
WaapModelResultLogger::Impl::logModelResult(
    Waap::Scores::ModelLoggingSettings &settings,
    IWaf2Transaction* transaction,
    Waf2ScanResult &res,
    string modelName,
    string otherModelName,
    double score,
    double otherScore)
{
    if (transaction == NULL) return;
    if (!Singleton::exists<I_Messaging>()) {
        dbgError(D_WAAP_MODEL_LOGGER) << "Messaging service is not available, will not log";
        return;
    }

    double score_diff = score - otherScore;
    if (settings.logLevel == Waap::Scores::ModelLogLevel::DIFF &&
        ! ((score_diff > 0 && score >= 1.5f && otherScore < 4.0f) ||
        (score_diff < 0 && score < 4.0f && otherScore >= 1.5f))) {
        return;
    }

    auto current_time = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();
    auto now = chrono::duration_cast<chrono::minutes>(current_time);

    WaapModelResult result = WaapModelResult(
        *transaction,
        res,
        modelName,
        otherModelName,
        score,
        otherScore,
        now.count()
        );

    if (settings.logToStream) logToStream(result, now);
    if (settings.logToS3) logToS3(result, transaction, now);
}

void WaapModelResultLogger::Impl::logToS3(WaapModelResult &result, IWaf2Transaction* transaction, chrono::minutes now)
{
    auto asset_state = transaction->getAssetState();
    string asset_id = (asset_state != nullptr) ? asset_state->m_assetId : "";
    auto asset_logs = logs.find(asset_id);
    if (asset_logs == logs.end()) {
        logs.emplace(asset_id, vector<WaapModelResult>());
    }
    logs.at(asset_id).push_back(result);
    if (shouldSendLogsToS3(now)) {
        sendLogsToS3();
    }
}

void WaapModelResultLogger::Impl::logToStream(WaapModelResult &result, chrono::minutes now)
{
    if (now - last_kusto_log_window > RATE_LIMIT_WINDOW_MINUTES) {
        last_kusto_log_window = now;
        sent_logs_count = 0;
    }
    else if (sent_logs_count > MAX_LOGS_PER_WINDOW) {
        return;
    }
    sent_logs_count++;
    dbgTrace(D_WAAP_MODEL_LOGGER) << "Logging WAAP model telemetry";

    auto maybeLogTriggerConf = getConfiguration<LogTriggerConf>("rulebase", "log");
    LogGenWrapper logGenWrapper(
        maybeLogTriggerConf,
        "WAAP Model Telemetry",
        ReportIS::Audience::SECURITY,
        LogTriggerConf::SecurityType::ThreatPrevention,
        ReportIS::Severity::CRITICAL,
        ReportIS::Priority::HIGH,
        false);

    LogGen& waap_log = logGenWrapper.getLogGen();
    waap_log.addMarkerSuffix(result.location);
    waap_log << LogField("httpuripath", result.uri);
    waap_log << LogField("matchedlocation", result.location);
    waap_log << LogField("matchedparameter", result.param);
    waap_log << LogField("matchedindicators", Waap::Util::vecToString(result.keywords), LogFieldOption::XORANDB64);
    waap_log << LogField("matchedsample", result.sample, LogFieldOption::XORANDB64);
    waap_log << LogField("waapkeywordsscore", (int)(result.otherScore * 100));
    waap_log << LogField("waapfinalscore", (int)(result.score * 100));
    waap_log << LogField("indicatorssource", result.modelName);
    waap_log << LogField("indicatorsversion", result.otherModelName);
}

bool WaapModelResultLogger::Impl::shouldSendLogsToS3(chrono::minutes now)
{
    if (now - last_sent_s3 > RATE_LIMIT_WINDOW_MINUTES) return true;
    for (const auto &asset_logs : logs) {
        if (asset_logs.second.size() >= max_logs) return true;
    }
    return false;
}

void WaapModelResultLogger::Impl::sendLogsToS3()
{
    dbgFlow(D_WAAP_MODEL_LOGGER) << "Sending logs to fog";

    I_Messaging *msg = Singleton::Consume<I_Messaging>::by<WaapComponent>();

    for (auto &asset_logs : logs) {
        if (asset_logs.second.empty()) {
            continue;
        }
        if (sent_files_count >= MAX_FILES_PER_WINDOW) {
            dbgInfo(D_WAAP_MODEL_LOGGER) << "Reached max files per window, will wait for next window";
            asset_logs.second.clear();
            continue;
        }
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        string tenant_id = agentDetails->getTenantId();
        string agent_id = agentDetails->getAgentId();
        string asset_id = asset_logs.first;
        if (Singleton::exists<I_InstanceAwareness>()) {
            I_InstanceAwareness* instance = Singleton::Consume<I_InstanceAwareness>::by<WaapComponent>();
            Maybe<string> uniqueId = instance->getUniqueID();
            if (uniqueId.ok())
            {
                agent_id += "/" + uniqueId.unpack();
            }
        }
        string uri = "/storage/waap/" +
                    tenant_id + "/" + asset_id + "/waap_model_results/window_" +
                    to_string(last_sent_s3.count()) + "-" + to_string(sent_files_count) +
                    "/" + agent_id + "/data.data";
        WaapModelReport report = WaapModelReport(asset_logs.second);

        dbgInfo(D_WAAP_MODEL_LOGGER) << "Sending logs for asset " << asset_logs.first <<
            ", length " << asset_logs.second.size() <<
            ", uri " << uri;
        msg->sendAsyncMessage(
            HTTPMethod::PUT,
            uri,
            report,
            MessageCategory::LOG
        );

        asset_logs.second.clear();
    }

    auto current_time = Singleton::Consume<I_TimeGet>::by<WaapComponent>()->getWalltime();
    auto now = chrono::duration_cast<chrono::minutes>(current_time);
    if (now - last_sent_s3 > RATE_LIMIT_WINDOW_MINUTES) {
        last_sent_s3 = now;
        sent_files_count = 0;
    } else {
        sent_files_count++;
    }
}

WaapModelResultLogger::Impl::~Impl()
{}
