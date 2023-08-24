// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

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

#include "nginx_attachment.h"

#include <pwd.h>
#include <grp.h>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <climits>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <stdarg.h>

#include <boost/range/iterator_range.hpp>
#include <boost/regex.hpp>

#include "nginx_attachment_config.h"
#include "nginx_attachment_opaque.h"
#include "nginx_parser.h"
#include "i_instance_awareness.h"
#include "common.h"
#include "config.h"
#include "singleton.h"
#include "i_mainloop.h"
#include "buffer.h"
#include "enum_array.h"
#include "shmem_ipc.h"
#include "i_http_manager.h"
#include "http_transaction_common.h"
#include "nginx_attachment_common.h"
#include "hash_combine.h"
#include "cpu/failopen_mode_status.h"
#include "attachment_registrator.h"
#include "cache.h"
#include "log_generator.h"
#include "report/report_enums.h"
#include "user_identifiers_config.h"
#include "agent_core_utilities.h"

#ifdef FAILURE_TEST
#include "intentional_failure.h"
#define SHOULD_FAIL(is_ok, type, indicator) intentional_failure_handler.shouldFail((is_ok), type, indicator)
#define DELAY_IF_NEEDED(type) intentional_failure_handler.delayIfNeeded(type);

#else
#define SHOULD_FAIL(is_ok, type, indicator) !(is_ok)
#define DELAY_IF_NEEDED(type)

#endif // FAILURE_TEST

USE_DEBUG_FLAG(D_NGINX_ATTACHMENT);
USE_DEBUG_FLAG(D_COMPRESSION);
USE_DEBUG_FLAG(D_METRICS_NGINX_ATTACHMENT);

using namespace std;

using ChunkType = ngx_http_chunk_type_e;

static const uint32_t corrupted_session_id = CORRUPTED_SESSION_ID;

class FailopenModeListener : public Listener<FailopenModeEvent>
{
public:
    FailopenModeListener() = default;

    void
    upon(const FailopenModeEvent &event) override
    {
        current_failopen_status = event.getFailopenMode();
    }

    bool
    isFailopenMode() const
    {
        return current_failopen_status;
    }

private:
    bool current_failopen_status = false;
};

void
IpcDebug(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...)
{
    if (!Debug::evalFlags(is_error ? Debug::DebugLevel::WARNING : Debug::DebugLevel::TRACE, D_NGINX_ATTACHMENT)) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    size_t len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    vector<char> message(len + 1);
    va_start(args, fmt);
    vsnprintf(&message[0], len + 1, fmt, args);
    va_end(args);

    Debug(
        file,
        func,
        line_num,
        is_error ? Debug::DebugLevel::WARNING : Debug::DebugLevel::TRACE,
        D_NGINX_ATTACHMENT
    ).getStreamAggr() << message.data();
}

class NginxAttachment::Impl
        :
    Singleton::Provide<I_StaticResourcesHandler>::From<NginxAttachment>
{
    static constexpr auto INSPECT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    static constexpr auto ACCEPT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
    static constexpr auto DROP = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
    static constexpr auto INJECT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT;
    static constexpr auto IRRELEVANT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
    static constexpr auto RECONF = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_RECONF;
    static constexpr auto WAIT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT;

public:
    Impl()
        :
#ifdef FAILURE_TEST
    intentional_failure_handler(),
#endif
    nginx_plugin_cpu_metric(true)
    {}

    void
    init()
    {
        dbgFlow(D_NGINX_ATTACHMENT) << "Initializing NGINX attachment";

        i_env = Singleton::Consume<I_Environment>::by<NginxAttachment>();
        timer = Singleton::Consume<I_TimeGet>::by<NginxAttachment>();
        i_socket = Singleton::Consume<I_Socket>::by<NginxAttachment>();
        mainloop = Singleton::Consume<I_MainLoop>::by<NginxAttachment>();
        http_manager = Singleton::Consume<I_HttpManager>::by<NginxAttachment>();
        i_transaction_table = Singleton::Consume<I_TableSpecific<SessionID>>::by<NginxAttachment>();
        inst_awareness = Singleton::Consume<I_InstanceAwareness>::by<NginxAttachment>();

        auto agent_type = getSetting<string>("agentType");
        bool is_nsaas_env = false;
        if (agent_type.ok() && (*agent_type == "CloudNative" || *agent_type == "VirtualNSaaS")) {
            is_nsaas_env = true;
        }

        if (is_nsaas_env && inst_awareness->getFamilyID().ok()) {
            mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::Offline,
                [this] ()
                {
                    while (true) {
                        if (!setActiveTenantAndProfile()) {
                            mainloop->yield(std::chrono::seconds(2));
                        } else {
                            break;
                        }
                    }
                },
                "Setting active tenant and profile for an NGINX based security app",
                false
            );
        }

        metric_report_interval = chrono::seconds(
            getConfigurationWithDefault<uint>(
                METRIC_PERIODIC_TIMEOUT,
                "Nginx Attachment",
                "metric reporting interval"
            )
        );

        num_of_nginx_ipc_elements = getProfileAgentSettingWithDefault<uint>(
            NUM_OF_NGINX_IPC_ELEMENTS, "nginxAttachment.numOfNginxIpcElements"
        );

        nginx_attachment_metric.init(
            "Nginx Attachment data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            true
        );
        nginx_attachment_metric.registerListener();

        nginx_intaker_metric.init(
            "Nginx Attachment Plugin data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            true
        );
        nginx_intaker_metric.registerListener();

        transaction_table_metric.init(
            "Nginx transaction table data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            true
        );
        transaction_table_metric.registerListener();

        nginx_plugin_cpu_metric.init(
            "Nginx Attachment Plugin CPU data",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            metric_report_interval,
            true
        );

        nginx_plugin_cpu_metric.registerContext<string>("Service Name", "Nginx Attachment");
        nginx_plugin_cpu_metric.registerListener();

#ifdef FAILURE_TEST
        intentional_failure_handler.init();
#endif

        generateAttachmentConfig();
        registerConfigLoadCb([this]() { generateAttachmentConfig(); });

        createStaticResourcesFolder();

        setCompressionDebugFunctions();

        setMetricHandlers();

        fail_open_mode_listener.registerListener();

        if (!initSocket()) {
            mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::System,
                [this] ()
                {
                    while(!initSocket()) {
                        mainloop->yield(true);
                    }
                },
                "Nginx Attachment IPC initializer"
            );
        }

        dbgInfo(D_NGINX_ATTACHMENT) << "Successfully initialized NGINX Attachment";
    }

    bool
    setActiveTenantAndProfile()
    {
        string container_id = inst_awareness->getFamilyID().unpack();
        if (container_id.empty()) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed getting a family ID";
            return false;
        }
        dbgTrace(D_NGINX_ATTACHMENT) << "Found a family ID: " << container_id;

        I_ShellCmd *shell_cmd = Singleton::Consume<I_ShellCmd>::by<NginxAttachment>();

        string cmd =
            "docker inspect --format='{{.Name}}' " + container_id  +
            " | awk -F'cp_nginx_gaia' '{print substr($2, index($2, \" \"))}'";
        auto maybe_tenant_profile_ids = shell_cmd->getExecOutput(cmd, 1000, false);
        dbgTrace(D_NGINX_ATTACHMENT) << "Checking for tenant and profile IDs with the command: " << cmd;

        if (!maybe_tenant_profile_ids.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed getting the tenant and progile IDs: "
                << cmd
                << ". Error :"
                << maybe_tenant_profile_ids.getErr();

            return false;
        }

        dbgWarning(D_NGINX_ATTACHMENT)
            << "Parsing the tenant and profile IDs from the container name: "
            << maybe_tenant_profile_ids.unpack();

        string tenant_profile_ids = maybe_tenant_profile_ids.unpack();
        tenant_profile_ids.erase(
            remove(tenant_profile_ids.begin(), tenant_profile_ids.end(), '\n'), tenant_profile_ids.end()
        );

        size_t delimeter_pos = tenant_profile_ids.find("_");
        if (delimeter_pos == string::npos) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Couldn't parse tenant and profile IDs from the container name: "
                << tenant_profile_ids;
            return false;
        }
        string tenant_id = tenant_profile_ids.substr(0, delimeter_pos);
        string profile_id = tenant_profile_ids.substr(delimeter_pos + 1);

        i_env->setActiveTenantAndProfile(tenant_id, profile_id);
        dbgTrace(D_NGINX_ATTACHMENT)
            << "NGINX attachment setting active context. Tenant ID: "
            << tenant_id
            << ", Profile ID: "
            << profile_id;

        return true;
    }

    void
    fini()
    {
        resetCompressionDebugFunctionsToStandardError();

        if (server_sock > 0) {
            i_socket->closeSocket(server_sock);
            server_sock = -1;
        }

        if (attachment_routine_id > 0 && mainloop->doesRoutineExist(attachment_routine_id)) {
            mainloop->stop(attachment_routine_id);
            attachment_routine_id = 0;
        }

        if (attachment_sock > 0) {
            i_socket->closeSocket(attachment_sock);
            attachment_sock = -1;
        }

        if (attachment_ipc != nullptr) {
            destroyIpc(attachment_ipc, 1);
            attachment_ipc = nullptr;
        }
    }

    bool
    registerStaticResource(const string &resource_name, const string &resource_path)
    {
        string dest_path = static_resources_path + "/" + resource_name;
        if (NGEN::Filesystem::exists(dest_path)) {
            dbgDebug(D_NGINX_ATTACHMENT) << "Static resource already exist. path: " << dest_path;
            return true;
        }

        if (!NGEN::Filesystem::copyFile(
            resource_path,
            dest_path,
            false,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to write the static resource to the shared memory. Resource name: "
                << resource_name
                << ", static resource's path: "
                << resource_path;
            return false;
        }

        dbgTrace(D_NGINX_ATTACHMENT)
            << "Successfully wrote the static resource to the shared memory. Resource Name: "
            << resource_name
            << ", static resource's path: "
            << resource_path;

        return true;
    }

    void
    printMetrics()
    {
        dbgDebug(D_METRICS_NGINX_ATTACHMENT)
            << "Total number of responses received: "
            << to_string(num_uncompressed_responses + num_compressed_responses)
            << ", number of uncompressed responses: "
            << to_string(num_uncompressed_responses)
            << ", number of compressed responses: "
            << to_string(num_compressed_responses);

        metrics_average_table_size =
            (i_transaction_table->count() + metrics_average_table_size * metrics_sample_count) /
            (metrics_sample_count + 1);

        metrics_sample_count++;
        dbgDebug(D_METRICS_NGINX_ATTACHMENT) << "Maximum transactions table size: " << metrics_max_table_size;
        dbgDebug(D_METRICS_NGINX_ATTACHMENT) << "Average transactions table size: " << metrics_average_table_size;
        dbgDebug(D_METRICS_NGINX_ATTACHMENT) << "Current transactions table size: " << i_transaction_table->count();
    }

    void
    preload()
    {
#ifdef FAILURE_TEST
        intentional_failure_handler.preload();
#endif
    }

private:
    bool
    registerAttachmentProcess(uint32_t nginx_user_id, uint32_t nginx_group_id, I_Socket::socketFd new_socket)
    {
        dbgAssert(server_sock > 0) << "Registration attempt occurred while registration socket is uninitialized";
#ifdef FAILURE_TEST
        bool did_fail_on_purpose = false;
#endif

        if (attachment_routine_id > 0 && mainloop->doesRoutineExist(attachment_routine_id)) {
            mainloop->stop(attachment_routine_id);
            attachment_routine_id = 0;
        }

        string curr_instance_unique_id = inst_awareness->getUniqueID().unpack();
        if (attachment_ipc != nullptr) {
            if (nginx_worker_user_id != nginx_user_id || nginx_worker_group_id != nginx_group_id) {
                destroyIpc(attachment_ipc, 1);
                attachment_ipc = nullptr;
            } else if (isCorruptedShmem(attachment_ipc, 1)) {
                dbgWarning(D_NGINX_ATTACHMENT)
                    << "Destroying shmem IPC for Attachment with corrupted shared memory. Attachment id: "
                    << curr_instance_unique_id;

                destroyIpc(attachment_ipc, 1);
                attachment_ipc = nullptr;
            } else {
                dbgInfo(D_NGINX_ATTACHMENT) << "Re-registering attachment with id: " << curr_instance_unique_id;
                uint max_registrations = getProfileAgentSettingWithDefault<uint>(
                    6,
                    "httpManager.maximumRegistrationsAllowed"
                );
                uint duration_of_registrations = getProfileAgentSettingWithDefault<uint>(
                    20000,
                    "httpManager.allowedDurationOfRegistrations"
                );
                chrono::milliseconds curr_times_diff = chrono::duration_cast<chrono::milliseconds>(
                    chrono::steady_clock::now() -
                    registration_duration_start
                );
                if (curr_times_diff < chrono::milliseconds(duration_of_registrations)) {
                    if (++curr_attachment_registrations_counter > max_registrations) {
                        destroyIpc(attachment_ipc, 1);
                        attachment_ipc = nullptr;

                        dbgWarning(D_NGINX_ATTACHMENT)
                            << "Attachment with id: "
                            << curr_instance_unique_id
                            << " reached maximum number of allowed registration attempts";

                        registration_duration_start = chrono::steady_clock::now();
                        curr_attachment_registrations_counter = 1;
                    }
                } else {
                    registration_duration_start = chrono::steady_clock::now();
                    curr_attachment_registrations_counter = 1;
                }
            }
        }

        if (attachment_ipc == nullptr) {
            attachment_ipc = initIpc(
                curr_instance_unique_id.c_str(),
                nginx_user_id,
                nginx_group_id,
                1,
                num_of_nginx_ipc_elements,
                IpcDebug
            );

            if (SHOULD_FAIL(
                attachment_ipc != nullptr,
                IntentionalFailureHandler::FailureType::InitializeConnectionChannel,
                &did_fail_on_purpose
            )) {
                dbgWarning(D_NGINX_ATTACHMENT) << "Failed to initialize communication channel with attachment";
                return false;
            }
        }

        dbgDebug(D_NGINX_ATTACHMENT) << "Successfully initialized shmem channel";
        nginx_worker_user_id = nginx_user_id;
        nginx_worker_group_id = nginx_group_id;
        instance_unique_id = curr_instance_unique_id;

        if (attachment_sock > 0 && attachment_sock != new_socket) {
            i_socket->closeSocket(attachment_sock);
        }
        attachment_sock = new_socket;

        uint8_t success = 1;
        vector<char> reg_success(reinterpret_cast<char *>(&success), reinterpret_cast<char *>(&success) + 1);
        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::WriteDataToSocket);
        bool res = i_socket->writeData(attachment_sock, reg_success);
        if (SHOULD_FAIL(
            res, IntentionalFailureHandler::FailureType::WriteDataToSocket, &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed to ack registration success to attachment";
            i_socket->closeSocket(attachment_sock);
            attachment_sock = -1;
            return false;
        }

        attachment_routine_id = mainloop->addFileRoutine(
            I_MainLoop::RoutineType::RealTime,
            attachment_sock,
            [this] () mutable
            {
                auto on_exit = make_scope_exit(
                    [this]()
                    {
                        nginx_attachment_event.notify();
                        nginx_attachment_event.resetAllCounters();
                        nginx_intaker_event.notify();
                        nginx_intaker_event.resetAllCounters();
                    }
                );

                while (isSignalPending()) {
                    if (!handleInspection()) break;
                }
            },
            "Nginx Attachment inspection handler",
            true
        );

        traffic_indicator = true;
        dbgInfo(D_NGINX_ATTACHMENT) << "Successfully registered attachment";

        nginx_attachment_event.addNetworkingCounter(nginxAttachmentEvent::networkVerdict::REGISTRATION_SUCCESS);
        nginx_attachment_event.notify();
        nginx_attachment_event.resetAllCounters();
        return true;
    }

private:
    bool
    handleInspection()
    {
        Maybe<vector<char>> comm_trigger = genError("comm trigger uninitialized");;

        static map<I_Socket::socketFd, bool> comm_status;
        if (comm_status.find(attachment_sock) == comm_status.end()) {
            comm_status[attachment_sock] = true;
        }

        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::ReceiveDataFromSocket);

        uint32_t signaled_session_id = 0;
        for (int retry = 0; retry < 3; retry++) {
            comm_trigger = i_socket->receiveData(attachment_sock, sizeof(signaled_session_id));
            if (comm_trigger.ok()) break;
        }

        bool did_fail_on_purpose = false;
        if (SHOULD_FAIL(
            comm_trigger.ok(),
            IntentionalFailureHandler::FailureType::ReceiveDataFromSocket,
            &did_fail_on_purpose
        )) {
            if (comm_status[attachment_sock] == true) {
                dbgDebug(D_NGINX_ATTACHMENT)
                    << "Failed to get signal from attachment socket "
                    << ", Socket: "
                    << attachment_sock
                    << ", Error: "
                    << (did_fail_on_purpose ? "Intentional Failure" : comm_trigger.getErr());
                comm_status[attachment_sock] = false;
            }
            return false;
        }

        signaled_session_id = *reinterpret_cast<const uint32_t *>(comm_trigger.unpack().data());
        comm_status.erase(attachment_sock);
        traffic_indicator = true;

        while (isDataAvailable(attachment_ipc)) {
            traffic_indicator = true;
            Maybe<pair<uint32_t, bool>> session_verdict = handleRequestFromQueue(attachment_ipc, signaled_session_id);
            if (!session_verdict.ok()) return true;

            uint32_t handled_session_id = session_verdict.unpack().first;
            bool is_signal_needed = session_verdict.unpack().second;
            if (is_signal_needed) {
                dbgTrace(D_NGINX_ATTACHMENT) << "Signaling attachment to read verdict";
                bool res = false;
                vector<char> session_id_data(
                    reinterpret_cast<char *>(&handled_session_id),
                    reinterpret_cast<char *>(&handled_session_id) + sizeof(handled_session_id)
                );

                DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::WriteDataToSocket);

                if (!SHOULD_FAIL(
                    true,
                    IntentionalFailureHandler::FailureType::WriteDataToSocket,
                    &did_fail_on_purpose
                )) {
                    for (int retry = 0; retry < 3; retry++) {
                        if (i_socket->writeData(attachment_sock, session_id_data)) {
                            dbgTrace(D_NGINX_ATTACHMENT)
                                << "Successfully sent signal to attachment to read verdict.";
                            res = true;
                            return true;
                        }

                        dbgDebug(D_NGINX_ATTACHMENT)
                            << "Failed to send ACK to attachment  (try number " << retry << ")";
                        mainloop->yield(true);
                    }
                }
                if (!res) {
                    dbgWarning(D_NGINX_ATTACHMENT) << "Failed to send ACK to attachment"
                        << (did_fail_on_purpose ? "[Intentional Failure]" : "");
                    return false;
                }
            }
        }

        return true;
    }

    bool
    isSignalPending()
    {
        if (attachment_sock < 0) return false;
        return i_socket->isDataAvailable(attachment_sock);
    }

    void
    setMetricHandlers()
    {
        chrono::seconds metrics_print_interval_sec = chrono::seconds(
            getConfigurationWithDefault<uint>(
                default_metrics_print_interval_sec,
                "HTTP manager",
                "Metrics printing interval in sec"
            )
        );
        auto metrics_print_interval_usec = chrono::duration_cast<chrono::microseconds>(metrics_print_interval_sec);
        mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::Offline,
            metrics_print_interval_usec,
            [&]() { printMetrics(); },
            "Nginx Attachment metric printer",
            false
        );
    }

    void
    setCompressionDebugFunctions()
    {
        setCompressionDebugFunction(
            CompressionUtilsDebugLevel::COMPRESSION_DBG_LEVEL_ERROR,
            [](const char *debug_message) { dbgError(D_COMPRESSION) << debug_message; }
        );
    }

    void
    deleteStaticResourcesFolder()
    {
        if (!NGEN::Filesystem::deleteDirectory(static_resources_path)) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to delete the static resources' folder. Folder's path: "
                << static_resources_path;
        } else {
        dbgTrace(D_NGINX_ATTACHMENT)
            << "Successfully deleted the static resources' folder. Folder's path: "
            << static_resources_path;
        }
    }

    void
    createStaticResourcesFolder()
    {
        static_resources_path = getConfigurationWithDefault(
            default_static_resources_path,
            "HTTP manager",
            "Static resources path"
        );

        dbgDebug(D_NGINX_ATTACHMENT)
            << "Trying to create the static resources' folder at path: "
            << static_resources_path;

        if (NGEN::Filesystem::exists(static_resources_path)) {
            dbgDebug(D_NGINX_ATTACHMENT) << "Static resources' folder already exists";
            return;
        }

        if (!NGEN::Filesystem::makeDir(static_resources_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to create a folder for transferring static resources to attachments. Folder's path: "
                << static_resources_path;
            return;
        }
        dbgTrace(D_NGINX_ATTACHMENT)
            << "Successfully created the static resources' folder. Folder's path: "
            << static_resources_path;
    }

    void
    generateAttachmentConfig()
    {
        auto on_exit = make_scope_exit(
            [this]()
            {
                if (attachment_ipc == nullptr) return;

                handleVerdictResponse(FilterVerdict(RECONF), attachment_ipc, 0, false);

                dbgDebug(D_NGINX_ATTACHMENT)
                    << "Sending verdict RECONF for NGINX attachment with UID: "
                    << attachment_ipc;
            }
        );

        auto tenant_header_key = getProfileAgentSetting<string>("tenantIdKey");
        if (tenant_header_key.ok()) NginxParser::tenant_header_key = tenant_header_key.unpack();

        HttpAttachmentConfig new_conf;
        new_conf.init();

        default_verdict = FilterVerdict(new_conf.getIsFailOpenModeEnabled() ? ACCEPT : DROP);

        if (attachment_config == new_conf) return;
        attachment_config = new_conf;
        num_of_nginx_ipc_elements = new_conf.getNumOfNginxElements();

        string settings_path = getConfigurationWithDefault<string>(
            SHARED_ATTACHMENT_CONF_PATH,
            "HTTP manager",
            "Shared settings path"
        );

        for (uint retries = 0 ; retries < 3 ; retries++) {
            if (remove(settings_path.c_str()) == 0) break;
            usleep(1);
        }

        ofstream setting_stream(settings_path, ofstream::out);
        if (!setting_stream.is_open()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Could not set new attachment settings. Error: shared settings file \""
                << settings_path
                << "\" could not be opened";
            mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::Offline,
// LCOV_EXCL_START Reason: coverage upgrade
                [this] () { generateAttachmentConfig(); },
// LCOV_EXCL_STOP
                "Nginx Attachment configuration generator",
                false
            );
            return;
        }

        cereal::JSONOutputArchive archive_out(setting_stream);
        attachment_config.save(archive_out);
    }

    void
    sendMetricToKibana(const ngx_http_cp_metric_data_t *received_metric_data)
    {
        nginx_intaker_event.addPluginMetricCounter(received_metric_data);
        nginx_intaker_event.notify();
        nginx_intaker_event.resetAllCounters();
    }

    string
    convertChunkTypeToString(ChunkType data_type)
    {
        switch (data_type) {
        case ChunkType::CONTENT_LENGTH:
            return "Content Length";
        case ChunkType::RESPONSE_CODE:
            return "Response Code";
        case ChunkType::RESPONSE_BODY:
            return "Response Body";
        case ChunkType::RESPONSE_HEADER:
            return "Response Header";
        case ChunkType::RESPONSE_END:
            return "Response End";
        case ChunkType::REQUEST_START:
            return "Request Start";
        case ChunkType::REQUEST_HEADER:
            return "Request Header";
        case ChunkType::REQUEST_BODY:
            return "Request Body";
        case ChunkType::REQUEST_END:
            return "Request End";
        case ChunkType::METRIC_DATA_FROM_PLUGIN:
            return "Metrics";
        case ChunkType::HOLD_DATA:
            return "HOLD_DATA";
        case ChunkType::COUNT:
            dbgAssert(false) << "Invalid 'COUNT' ChunkType";
            return "";
        }
        dbgAssert(false) << "ChunkType was not handled by the switch case";
        return "";
    }

    FilterVerdict
    handleStartTransaction(const Buffer &data)
    {
        if (data.size() == 0) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Could not handle new transaction with an empty buffer. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict());
            return default_verdict;
        }

        NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
        auto rule_by_ctx = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
        if (rule_by_ctx.ok()) {
            BasicRuleConfig rule = rule_by_ctx.unpack();
            opaque.setSavedData("assetId", rule.getAssetId(), EnvKeyAttr::LogSection::SOURCEANDDATA);
            opaque.setSavedData("assetName", rule.getAssetName(), EnvKeyAttr::LogSection::SOURCEANDDATA);
        }
        return http_manager->inspect(opaque.getTransactionData());
    }

    FilterVerdict
    handleResponseCode(const Buffer &data)
    {
        auto status_code = NginxParser::parseResponseCode(data);
        if (!status_code.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse response status code. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << status_code.getErr();
            return default_verdict;
        }

        return http_manager->inspect(status_code.unpack());
    }

    FilterVerdict
    handleContentLength(const Buffer &data)
    {
        auto content_len = NginxParser::parseContentLength(data);
        if (!content_len.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse response content length. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << content_len.getErr();
            return default_verdict;
        }

        ModificationList mod_buff_list;
        mod_buff_list.emplace_back(INJECT_POS_IRRELEVANT, ModificationType::REPLACE, string("Content-Length"));

        FilterVerdict verdict(INJECT);
        verdict.addModifications(mod_buff_list, 0);

        return verdict;
    }

    template <typename M>
    FilterVerdict
    handleModifiableChunk(const Maybe<M> &chunk, const string &chunk_desc, bool is_request)
    {
        if (!chunk.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse "
                << chunk_desc
                << ". Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << chunk.getErr();
            return default_verdict;
        }

        return http_manager->inspect(*chunk, is_request);
    }

    template <typename M>
    FilterVerdict
    handleMultiModifiableChunks(const vector<M> &chunks, bool is_request)
    {
        FilterVerdict injection_verdict(INJECT);
        bool injection_required = false;
        for (const M &chunk : chunks) {
            FilterVerdict cur_verdict = http_manager->inspect(chunk, is_request);
            if (cur_verdict.getVerdict() == ACCEPT ||
                cur_verdict.getVerdict() == DROP   ||
                cur_verdict.getVerdict() == WAIT) {
                return cur_verdict;
            }

            if (cur_verdict.getVerdict() == INJECT) {
                injection_verdict.addModifications(cur_verdict);
                injection_required = true;
            }
        }
        if (!injection_required) return FilterVerdict();

        return injection_verdict;
    }

    template <typename M>
    FilterVerdict
    handleMultiModifiableChunks(const Maybe<vector<M>> &chunks, const string &chunk_desc, bool is_request)
    {
        if (!chunks.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse "
                << chunk_desc
                << ". Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << chunks.getErr();
            return default_verdict;
        }

        return handleMultiModifiableChunks(chunks.unpack(), is_request);
    }

    void
    setResponseContentEncoding(const CompressionType content_encoding)
    {
        if (content_encoding == HttpTransactionData::default_response_content_encoding) {
            dbgDebug(D_NGINX_ATTACHMENT) << "New content encoding is the default. Skipping change of currect state";
            return;
        }
        auto &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
        auto &transaction_data = opaque.getTransactionData();

        transaction_data.setResponseContentEncoding(content_encoding);
    }

    void
    updateMetrics(const CompressionType response_content_encoding)
    {
        if (response_content_encoding == CompressionType::NO_COMPRESSION) {
            num_uncompressed_responses++;
        } else {
            num_compressed_responses++;
        }
    }

    FilterVerdict
    handleResponseHeaders(const Buffer &headers_data)
    {
        dbgFlow(D_NGINX_ATTACHMENT) << "Handling response headers";
        bool did_fail_on_purpose = false;
        auto response_headers_maybe = NginxParser::parseResponseHeaders(headers_data);
        if (SHOULD_FAIL(
            response_headers_maybe.ok(), IntentionalFailureHandler::FailureType::ParsingResponse, &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse response headers. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << (did_fail_on_purpose ? "Intentional Failure" : response_headers_maybe.getErr());
            return default_verdict;
        }
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully parsed response headers";

        auto response_headers = response_headers_maybe.unpack();
        auto parsed_content_encoding_maybe = NginxParser::parseContentEncoding(response_headers);
        if (SHOULD_FAIL(
            parsed_content_encoding_maybe.ok(),
            IntentionalFailureHandler::FailureType::ParsingResponse,
            &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to parse content encoding from response headers. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict())
                << ", Error: "
                << (did_fail_on_purpose ? "Intentional Failure" : parsed_content_encoding_maybe.getErr());
            return default_verdict;
        }
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully parsed response's content encoding";

        auto parsed_content_encoding = parsed_content_encoding_maybe.unpack();
        setResponseContentEncoding(parsed_content_encoding);
        updateMetrics(parsed_content_encoding);

        return handleMultiModifiableChunks(response_headers, false);
    }

    FilterVerdict
    handleResponseBody(const Buffer &data)
    {
        auto &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
        auto &transaction_data = opaque.getTransactionData();

        CompressionType content_encoding = transaction_data.getResponseContentEncoding();
        CompressionStream *compression_stream = content_encoding == CompressionType::NO_COMPRESSION ?
            nullptr :
            opaque.getResponseCompressionStream();
        auto http_response_body_maybe = NginxParser::parseResponseBody(data, compression_stream);

        return handleModifiableChunk(http_response_body_maybe, "response body", false);
    }

    FilterVerdict
    handleChunkedData(ChunkType chunk_type, const Buffer &data)
    {
        ScopedContext event_type;
        event_type.registerValue<ngx_http_chunk_type_e>("HTTP Chunk type", chunk_type);

        auto rule_by_ctx = getConfiguration<BasicRuleConfig>("rulebase", "rulesConfig");
        if (!rule_by_ctx.ok() && chunk_type > ChunkType::REQUEST_HEADER) {
            ngx_http_cp_verdict_e verdict_action =
                getSettingWithDefault<bool>(false, "allowOnlyDefinedApplications") ? DROP : ACCEPT;

            dbgDebug(D_NGINX_ATTACHMENT)
                << "No policy rule was found for the current context. Setting verdict to "
                << verdictToString(verdict_action);

            return FilterVerdict(verdict_action);
        }

        switch (chunk_type) {
            case ChunkType::REQUEST_START:
                return handleStartTransaction(data);
            case ChunkType::REQUEST_HEADER:
                return handleMultiModifiableChunks(NginxParser::parseRequestHeaders(data), "request header", true);
            case ChunkType::REQUEST_BODY:
                return handleModifiableChunk(NginxParser::parseRequestBody(data), "request body", true);
            case ChunkType::REQUEST_END: {
                i_transaction_table->setExpiration(chrono::hours(1));
                return FilterVerdict(http_manager->inspectEndRequest());
            }
            case ChunkType::RESPONSE_CODE: {
                i_transaction_table->setExpiration(chrono::minutes(1));
                return handleResponseCode(data);
            }
            case ChunkType::CONTENT_LENGTH: {
                return handleContentLength(data);
            }
            case ChunkType::RESPONSE_HEADER:
                return handleResponseHeaders(data);
            case ChunkType::RESPONSE_BODY:
                nginx_attachment_event.addResponseInspectionCounter(1);
                return handleResponseBody(data);
            case ChunkType::RESPONSE_END:
                return FilterVerdict(http_manager->inspectEndTransaction());
            case ChunkType::METRIC_DATA_FROM_PLUGIN:
                return FilterVerdict(ngx_http_cp_verdict::TRAFFIC_VERDICT_IRRELEVANT);
            case ChunkType::HOLD_DATA:
                return FilterVerdict(http_manager->inspectDelayedVerdict());
            case ChunkType::COUNT:
                break;
        }
        dbgWarning(D_NGINX_ATTACHMENT)
            << "Received invalid 'ChunkType' chunk_type enum. Returning default verdict: "
            << verdictToString(default_verdict.getVerdict())
            << ", enum: "
            << static_cast<int>(chunk_type);
        return default_verdict;
    }

    void
    handleModifiedResponse(
        SharedMemoryIPC *ipc,
        const vector<EventModifications> &modifications_lists,
        uint32_t modifications_amount,
        vector<const char *> &verdict_data,
        vector<uint16_t> &verdict_data_sizes,
        bool is_header)
    {
        dbgFlow(D_NGINX_ATTACHMENT)
            << "Handling Injection of HTTP session modification data. Modifications amount: "
            << modifications_amount;

        vector<ngx_http_cp_inject_data> injection_data_persistency(modifications_amount);
        for (const EventModifications &modifications : modifications_lists) {
            for (const ModificationBuffer &modification_buffer_list : modifications.second) {
                ngx_http_cp_inject_data injection_data;
                injection_data.orig_buff_index = modifications.first;
                injection_data.injection_pos = std::get<0>(modification_buffer_list);
                injection_data.mod_type = std::get<1>(modification_buffer_list);
                injection_data.injection_size = std::get<2>(modification_buffer_list).size();
                injection_data.is_header = is_header ? 1 : 0;
                injection_data_persistency.push_back(injection_data);
                verdict_data.push_back(reinterpret_cast<const char *>(&injection_data_persistency.back()));
                verdict_data_sizes.push_back(sizeof(injection_data));

                const Buffer &modification_data = std::get<2>(modification_buffer_list);
                verdict_data.push_back(reinterpret_cast<const char *>(modification_data.data()));
                verdict_data_sizes.push_back(modification_data.size());

                dbgTrace(D_NGINX_ATTACHMENT)
                    << "Added modification ("
                    << injection_data_persistency.size()
                    << " out of "
                    << modifications_amount
                    << ") data to current session data. Modification position: "
                    << injection_data.injection_pos
                    << ", Modification size: "
                    << injection_data.injection_size
                    <<",: single_inject_data.is_header: "
                    << to_string(injection_data.is_header)
                    << ", Original buffer index: "
                    << to_string(injection_data.orig_buff_index)
                    << ", Modification data: "
                    << dumpHex(modification_data);
            }
        }

        sendChunkedData(ipc, verdict_data_sizes.data(), verdict_data.data(), verdict_data.size());
    }

    void
    handleCustomWebResponse(
        SharedMemoryIPC *ipc,
        vector<const char *> &verdict_data,
        vector<uint16_t> &verdict_data_sizes)
    {
        ngx_http_cp_web_response_data_t web_response_data;

        WebTriggerConf web_trigger_conf = getConfigurationWithDefault<WebTriggerConf>(
            WebTriggerConf::default_trigger_conf,
            "rulebase",
            "webUserResponse"
        );

        string uuid;
        if (i_transaction_table->hasState<NginxAttachmentOpaque>()) {
            NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
            uuid = opaque.getSessionUUID();
        }
        web_response_data.uuid_size =
            string("Incident Id: ").length() + uuid.size();

        if (web_trigger_conf.getDetailsLevel() == "Redirect") {
            web_response_data.response_data.redirect_data.redirect_location_size =
                web_trigger_conf.getRedirectURL().size();
            web_response_data.response_data.redirect_data.add_event_id = web_trigger_conf.getAddEventId() ? 1 : 0;
            web_response_data.web_repsonse_type = static_cast<uint8_t>(ngx_web_response_type_e::REDIRECT_WEB_RESPONSE);
        } else {
            web_response_data.response_data.custom_response_data.title_size =
                web_trigger_conf.getResponseTitle().size();
            web_response_data.response_data.custom_response_data.body_size = web_trigger_conf.getResponseBody().size();
            web_response_data.response_data.custom_response_data.response_code = web_trigger_conf.getResponseCode();
            web_response_data.web_repsonse_type = static_cast<uint8_t>(ngx_web_response_type_e::CUSTOM_WEB_RESPONSE);
        }

        verdict_data.push_back(reinterpret_cast<const char *>(&web_response_data));
        verdict_data_sizes.push_back(sizeof(ngx_http_cp_web_response_data_t));

        if (web_trigger_conf.getDetailsLevel() == "Redirect") {
            verdict_data.push_back(reinterpret_cast<const char *>(web_trigger_conf.getRedirectURL().data()));
            verdict_data_sizes.push_back(web_trigger_conf.getRedirectURL().size());
        } else {
            verdict_data.push_back(reinterpret_cast<const char *>(web_trigger_conf.getResponseTitle().data()));
            verdict_data_sizes.push_back(web_trigger_conf.getResponseTitle().size());

            verdict_data.push_back(reinterpret_cast<const char *>(web_trigger_conf.getResponseBody().data()));
            verdict_data_sizes.push_back(web_trigger_conf.getResponseBody().size());
        }

        verdict_data.push_back(reinterpret_cast<const char *>(uuid.data()));
        verdict_data_sizes.push_back(uuid.size());

        if (web_trigger_conf.getDetailsLevel() == "Redirect") {
            dbgTrace(D_NGINX_ATTACHMENT)
                << "Added custom redirect response to current session."
                << ", Redirect Location: "
                << web_trigger_conf.getRedirectURL()
                << " (redirect location size: "
                << static_cast<uint>(web_response_data.response_data.redirect_data.redirect_location_size)
                << ")"
                << ", Should add event id to header: "
                << static_cast<uint>(web_response_data.response_data.redirect_data.add_event_id)
                << ", UUID: "
                << uuid
                << " (UUID size: "
                << static_cast<uint>(web_response_data.uuid_size)
                << ")";
        } else {
            dbgTrace(D_NGINX_ATTACHMENT)
                << "Added custom response to current session."
                << "Response code:  "
                << static_cast<uint>(web_response_data.response_data.custom_response_data.response_code)
                << ", Title: "
                << web_trigger_conf.getResponseTitle()
                << " (title size: "
                << static_cast<uint>(web_response_data.response_data.custom_response_data.title_size)
                << "), Body: "
                << web_trigger_conf.getResponseBody()
                << " (body size: "
                << static_cast<uint>(web_response_data.response_data.custom_response_data.body_size)
                << "), UUID: "
                << uuid
                << " (UUID size: "
                << static_cast<uint>(web_response_data.uuid_size)
                << ")";
        }

        sendChunkedData(ipc, verdict_data_sizes.data(), verdict_data.data(), verdict_data.size());
    }

    void
    handleVerdictResponse(const FilterVerdict &verdict, SharedMemoryIPC *ipc, SessionID session_id, bool is_header)
    {
        ngx_http_cp_reply_from_service_t verdict_to_send;
        verdict_to_send.verdict = static_cast<uint16_t>(verdict.getVerdict());
        verdict_to_send.session_id = session_id;

        vector<const char *> verdict_fragments = { reinterpret_cast<const char *>(&verdict_to_send) };
        vector<uint16_t> fragments_sizes = { sizeof(verdict_to_send) };

        if (verdict.getVerdict() == INJECT) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::INJECT);
            verdict_to_send.modification_count = verdict.getModificationsAmount();
            return handleModifiedResponse(
                ipc,
                verdict.getModifications(),
                verdict.getModificationsAmount(),
                verdict_fragments,
                fragments_sizes,
                is_header
            );
        }

        if (verdict.getVerdict() == DROP) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::DROP);
            verdict_to_send.modification_count = 1;
            return handleCustomWebResponse(ipc, verdict_fragments, fragments_sizes);
        }

        if (verdict.getVerdict() == ACCEPT) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::ACCEPT);
        } else if (verdict.getVerdict() == INSPECT) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::INSPECT);
        } else if (verdict.getVerdict() == IRRELEVANT) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::IRRELEVANT);
        } else if (verdict.getVerdict() == RECONF) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::RECONF);
        } else if (verdict.getVerdict() == WAIT) {
            nginx_attachment_event.addTrafficVerdictCounter(nginxAttachmentEvent::trafficVerdict::WAIT);
        }

        sendChunkedData(ipc, fragments_sizes.data(), verdict_fragments.data(), verdict_fragments.size());
    }

// LCOV_EXCL_START Reason: cannot test dump of memory raw data (written in c) during UT
    const string
    dumpIpcWrapper(SharedMemoryIPC *attachment_ipc)
    {
        dumpIpcMemory(attachment_ipc);
        return "";
    }
// LCOV_EXCL_STOP

    bool
    isFailOpenTriggered() const
    {
        return attachment_config.getIsFailOpenModeEnabled() && fail_open_mode_listener.isFailopenMode();
    }

    void
    handleFailureMode(SharedMemoryIPC *attachment_ipc, uint32_t cur_session_id)
    {
        popData(attachment_ipc);
        while (isDataAvailable(attachment_ipc)) {
            Maybe<pair<uint16_t, const char *>> read_data = readData(attachment_ipc);
            if (!read_data.ok()) break;

            uint16_t incoming_data_size = read_data.unpack().first;
            const char *incoming_data = read_data.unpack().second;
            if (incoming_data_size == 0 || incoming_data == nullptr) {
                dbgWarning(D_NGINX_ATTACHMENT) << "No data received from NGINX attachment";
                break;
            }

            auto transaction_data = reinterpret_cast<const ngx_http_cp_request_data_t *>(incoming_data);
            if (transaction_data->session_id != cur_session_id) break;

            popData(attachment_ipc);
        }

        handleVerdictResponse(
            FilterVerdict(ACCEPT),
            attachment_ipc,
            cur_session_id,
            false
        );
    }

    Maybe<pair<uint16_t, const char *>>
    readData(SharedMemoryIPC *attachment_ipc)
    {
        const char *incoming_data = nullptr;
        uint16_t incoming_data_size;

        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::GetDataFromAttchment);
        int res = receiveData(attachment_ipc, &incoming_data_size, &incoming_data);
        if (res == corrupted_shmem_error) {
            dbgError(D_NGINX_ATTACHMENT)
                << "Failed to receive data from corrupted IPC Resetting the IPC"
                << dumpIpcWrapper(attachment_ipc);

            resetIpc(attachment_ipc, num_of_nginx_ipc_elements);
            nginx_attachment_event.addNetworkingCounter(nginxAttachmentEvent::networkVerdict::CONNECTION_FAIL);
            return genError("Failed to receive data from corrupted IPC");
        }

        bool did_fail_on_purpose = false;
        if (SHOULD_FAIL(
            res == 0, IntentionalFailureHandler::FailureType::GetDataFromAttchment, &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed to receive data from NGINX attachment";
            nginx_attachment_event.addNetworkingCounter(nginxAttachmentEvent::networkVerdict::CONNECTION_FAIL);
            return pair<uint16_t, const char *>(0, nullptr);
        }

        if (SHOULD_FAIL(
            incoming_data_size >= sizeof(ngx_http_cp_request_data_t),
            IntentionalFailureHandler::FailureType::GetDataFromAttchment,
            &did_fail_on_purpose
        )) {
            dbgError(D_NGINX_ATTACHMENT)
                << "Corrupted transaction raw data received from NGINX attachment, size received: "
                << incoming_data_size
                << " is lower than ngx_http_cp_request_data_t size="
                << sizeof(ngx_http_cp_request_data_t)
                << ". Resetting IPC"
                << dumpIpcWrapper(attachment_ipc)
                << (did_fail_on_purpose ? "[Intentional Failure]" : "");

            popData(attachment_ipc);
            resetIpc(attachment_ipc, num_of_nginx_ipc_elements);
            nginx_attachment_event.addNetworkingCounter(nginxAttachmentEvent::networkVerdict::CONNECTION_FAIL);
            return genError("Data received is smaller than expected");
        }

        return make_pair(incoming_data_size, incoming_data);
    }

    Maybe<pair<uint32_t, bool>>
    handleRequestFromQueue(SharedMemoryIPC *attachment_ipc, uint32_t signaled_session_id)
    {
        Maybe<pair<uint16_t, const char *>> read_data = readData(attachment_ipc);
        if (!read_data.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed to read data. Error: " << read_data.getErr();
            return make_pair(corrupted_session_id, true);
        }

        uint16_t incoming_data_size = read_data.unpack().first;
        const char *incoming_data = read_data.unpack().second;
        if (incoming_data_size == 0 || incoming_data == nullptr) {
            dbgWarning(D_NGINX_ATTACHMENT) << "No data received from NGINX attachment";
            return make_pair(corrupted_session_id, false);
        }

        const ngx_http_cp_request_data_t *transaction_data =
            reinterpret_cast<const ngx_http_cp_request_data_t *>(incoming_data);

        Maybe<ChunkType> chunked_data_type = convertToEnum<ChunkType>(transaction_data->data_type);
        if (!chunked_data_type.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Could not convert "
                <<  static_cast<int>(transaction_data->data_type)
                << " to ChunkType enum. Resetting IPC"
                << dumpIpcWrapper(attachment_ipc);
            popData(attachment_ipc);
            resetIpc(attachment_ipc, num_of_nginx_ipc_elements);
            nginx_attachment_event.addNetworkingCounter(nginxAttachmentEvent::networkVerdict::CONNECTION_FAIL);
            return make_pair(corrupted_session_id, true);
        }

        if (chunked_data_type.unpack() == ChunkType::METRIC_DATA_FROM_PLUGIN) {
            const ngx_http_cp_metric_data_t *recieved_metric_data =
                reinterpret_cast<const ngx_http_cp_metric_data_t *>(incoming_data);
            sendMetricToKibana(recieved_metric_data);
            popData(attachment_ipc);
            return pair<uint32_t, bool>(0, false);
        }

        dbgTrace(D_NGINX_ATTACHMENT)
            << "Reading "
            << incoming_data_size
            <<" bytes "
            << convertChunkTypeToString(*chunked_data_type)
            << "(type = "
            << static_cast<int>(*chunked_data_type)
            << ") of data from NGINX attachment for session ID: "
            << transaction_data->session_id;

        const uint32_t cur_session_id = transaction_data->session_id;
        if (signaled_session_id != cur_session_id) {
            dbgDebug(D_NGINX_ATTACHMENT)
                << "Ignoring inspection of irrelevant transaction. Signaled session ID: "
                << signaled_session_id
                << ", Inspected Session ID: "
                << cur_session_id;

            popData(attachment_ipc);
            return make_pair(cur_session_id, false);
        }

        if (isFailOpenTriggered()) {
            dbgTrace(D_NGINX_ATTACHMENT)
                << "Agent is set to Fail Open Mode. Passing inspection and returning Accept."
                << " Session ID: "
                <<  cur_session_id
                << ", Chunked data type: "
                << static_cast<int>(*chunked_data_type);

            if (i_transaction_table->hasEntry(cur_session_id)) {
                i_transaction_table->deleteEntry(cur_session_id);
            }

            handleFailureMode(attachment_ipc, cur_session_id);
            return make_pair(cur_session_id, *chunked_data_type == ChunkType::REQUEST_START);
        }

        if (!setActiveTransactionEntry(transaction_data->session_id, chunked_data_type.unpack())) {
            popData(attachment_ipc);
            return make_pair(cur_session_id, false);
        }

        const Buffer inspection_data(
            transaction_data->data,
            incoming_data_size - sizeof(ngx_http_cp_request_data_t),
            Buffer::MemoryType::VOLATILE
        );

        if (*chunked_data_type == ChunkType::REQUEST_START && !createTransactionState(inspection_data)) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to handle new request. Returning default verdict: "
                << verdictToString(default_verdict.getVerdict());

            handleVerdictResponse(
                default_verdict,
                attachment_ipc,
                transaction_data->session_id,
                false
            );
            popData(attachment_ipc);
            removeTransactionEntry(transaction_data->session_id);
            return make_pair(cur_session_id, true);
        }

        if (i_transaction_table != nullptr) {
            transaction_table_event.setTransactionTableSize(i_transaction_table->count());
            transaction_table_event.notify();
        }

        NginxAttachmentOpaque &opaque = i_transaction_table->getState<NginxAttachmentOpaque>();
        opaque.activateContext();

        FilterVerdict verdict = handleChunkedData(*chunked_data_type, inspection_data);

        bool is_header =
            *chunked_data_type == ChunkType::REQUEST_HEADER  ||
            *chunked_data_type == ChunkType::RESPONSE_HEADER ||
            *chunked_data_type == ChunkType::CONTENT_LENGTH;
        handleVerdictResponse(verdict, attachment_ipc, transaction_data->session_id, is_header);

        bool is_final_verdict = verdict.getVerdict() == ACCEPT ||
                                verdict.getVerdict() == DROP   ||
                                verdict.getVerdict() == IRRELEVANT;

        dbgTrace(D_NGINX_ATTACHMENT)
            << "Request handled successfully - for"
            << " NGINX attachment session ID: "
            << transaction_data->session_id
            << " verdict: "
            << verdictToString(verdict.getVerdict())
            << " verdict_data_code="
            << static_cast<int>(verdict.getVerdict());

        popData(attachment_ipc);

        opaque.deactivateContext();
        if (is_final_verdict) {
            removeTransactionEntry(transaction_data->session_id);
        } else {
            i_transaction_table->unsetActiveKey();
        }

        bool should_signal = (is_final_verdict || !isDataAvailable(attachment_ipc));
        return make_pair(cur_session_id, should_signal);
    }

    bool
    createTransactionState(const Buffer &data)
    {
        auto transaction_data = NginxParser::parseStartTrasaction(data);
        if (!transaction_data.ok()) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed to parse new transaction data: " << transaction_data.getErr();
            return false;
        }
        if (i_transaction_table->hasState<NginxAttachmentOpaque>()) {
            dbgInfo(D_NGINX_ATTACHMENT) << "Trying to recreate a state of type NginxAttachmentOpaque";
            i_transaction_table->deleteState<NginxAttachmentOpaque>();
        }

        if (!i_transaction_table->createState<NginxAttachmentOpaque>(transaction_data.unpack())) {
            dbgWarning(D_NGINX_ATTACHMENT) << "Failed to create attachment opaque";
            return false;
        }

        return true;
    }

    bool
    setActiveTransactionEntry(const SessionID session_id, ChunkType data_type)
    {
        if (data_type == ChunkType::REQUEST_START && i_transaction_table->hasEntry(session_id)) {
            dbgInfo(D_NGINX_ATTACHMENT) << "Recreating transaction entry. Key: " << session_id;
            i_transaction_table->deleteEntry(session_id);
        }

        if (!i_transaction_table->hasEntry(session_id)) {
            if (data_type != ChunkType::REQUEST_START) {
                dbgDebug(D_NGINX_ATTACHMENT)
                    << "Transaction entry does not exist for session ID: "
                    << session_id
                    << " ignoring inspection for data type != request start";
                return false;
            }

            if (!i_transaction_table->createEntry(session_id, chrono::minutes(1))) {
                dbgWarning(D_NGINX_ATTACHMENT)
                    << "Failed to create table entry for transaction with session ID: " << session_id;
                return false;
            }

            dbgDebug(D_NGINX_ATTACHMENT) << "New transaction entry created. Key: " << session_id;
            if (i_transaction_table->count() > metrics_max_table_size) {
                metrics_max_table_size = i_transaction_table->count();
            }
        }
        if (!i_transaction_table->setActiveKey(session_id)) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to set active table entry for transaction. Session ID: " << session_id;
            return false;
        }
        dbgTrace(D_NGINX_ATTACHMENT) << "Entry exists - setting it active";

        return true;
    }

    void
    removeTransactionEntry(const SessionID session_id)
    {
        i_transaction_table->unsetActiveKey();
        bool entry_deleted = i_transaction_table->deleteEntry(session_id);

        if (!entry_deleted) {
            dbgWarning(D_NGINX_ATTACHMENT) << "No Entry to delete, Session ID: " << session_id << ".";
        } else {
            dbgTrace(D_NGINX_ATTACHMENT) << "Removed the transaction entry";
        }
    }

    string
    verdictToString(const EventVerdict &verdict)
    {
        switch (verdict.getVerdict()) {
            case DROP:
                return "DROP";
            case ACCEPT:
                return "ACCEPT";
            case INJECT:
                return "INJECT";
            case INSPECT:
                return "INSPECT";
            case IRRELEVANT:
                return "IRRELEVANT";
            case RECONF:
                return "RECONF";
            case WAIT:
                return "WAIT";
        }
        dbgAssert(false) << "Invalid EventVerdict enum: " << static_cast<int>(verdict.getVerdict());
        return string();
    }

    bool
    initSocket()
    {
        bool did_fail_on_purpose = false;
        string shared_verdict_signal_path = getConfigurationWithDefault<string>(
            SHARED_VERDICT_SIGNAL_PATH,
            "HTTP manager",
            "Shared verdict signal path"
        );

        size_t last_slash_idx = shared_verdict_signal_path.find_last_of("/");
        string directory_path = shared_verdict_signal_path.substr(0, last_slash_idx);
        mkdir(directory_path.c_str(), 0777);

        auto id = inst_awareness->getUniqueID();
        static bool already_failed_on_id = false;
        if (SHOULD_FAIL(id.ok(), IntentionalFailureHandler::FailureType::GetInstanceID, &did_fail_on_purpose)) {
            if (!already_failed_on_id) {
                dbgError(D_NGINX_ATTACHMENT)
                    << "Failed to get instance ID. Error: "
                    << (did_fail_on_purpose ? "Intentional Failure" : id.getErr());
                already_failed_on_id = true;
            } else {
                dbgWarning(D_NGINX_ATTACHMENT)
                    << "Failed to get instance ID. Error: "
                    << (did_fail_on_purpose ? "Intentional Failure" : id.getErr());
            }
            return false;
        }
        already_failed_on_id = false;
        shared_verdict_signal_path += ("-" + id.unpack());

        Maybe<I_Socket::socketFd> sock = i_socket->genSocket(
            I_Socket::SocketType::UNIX,
            true,
            true,
            shared_verdict_signal_path
        );
        if (SHOULD_FAIL(
            sock.ok(), IntentionalFailureHandler::FailureType::CreateSocket, &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to open a server socket. Error: "
                << (did_fail_on_purpose ? "Intentional Failure" : sock.getErr());
            return false;
        }

        dbgAssert(sock.unpack() > 0) << "The generated server socket is OK, yet negative";
        server_sock = sock.unpack();

        I_MainLoop::Routine accept_attachment_routine =
            [this] ()
            {
                dbgAssert(inst_awareness->getUniqueID().ok())
                    << "NGINX attachment Initialized without Instance Awareness";

                bool did_fail_on_purpose = false;
                DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::AcceptSocket);
                Maybe<I_Socket::socketFd> new_sock = i_socket->acceptSocket(server_sock, true);
                if (SHOULD_FAIL(
                    new_sock.ok(), IntentionalFailureHandler::FailureType::AcceptSocket, &did_fail_on_purpose
                )) {
                    dbgWarning(D_NGINX_ATTACHMENT) << "Failed to accept a new socket. Error: "
                    << (did_fail_on_purpose ? "Intentional Failure" : new_sock.getErr());
                    return;
                }
                dbgAssert(new_sock.unpack() > 0) << "The generated client socket is OK, yet negative";
                I_Socket::socketFd new_attachment_socket = new_sock.unpack();

                Maybe<string> uid = getUidFromSocket(new_attachment_socket);
                Maybe<uint32_t> nginx_user_id = readIdFromSocket(new_attachment_socket);
                Maybe<uint32_t> nginx_group_id = readIdFromSocket(new_attachment_socket);
                DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::RegisterAttchment);
                if (SHOULD_FAIL(
                    nginx_user_id.ok() && nginx_group_id.ok() && uid.ok(),
                    IntentionalFailureHandler::FailureType::RegisterAttchment,
                    &did_fail_on_purpose
                )) {
                    string err = "Undefined";
                    if (!nginx_user_id.ok()) {
                        err = nginx_user_id.getErr();
                    } else if (!uid.ok()) {
                        err = uid.getErr();
                    } else if (!nginx_group_id.ok()) {
                        err = nginx_group_id.getErr();
                    }
                    dbgWarning(D_NGINX_ATTACHMENT) << "Failed to register new attachment. Error: "
                    << (did_fail_on_purpose ? "Intentional Failure" : err);
                    i_socket->closeSocket(new_attachment_socket);
                    new_attachment_socket = -1;

                    nginx_attachment_event.addNetworkingCounter(
                        nginxAttachmentEvent::networkVerdict::REGISTRATION_FAIL
                    );
                    nginx_attachment_event.notify();
                    nginx_attachment_event.resetAllCounters();
                    return;
                }

                if (!registerAttachmentProcess(*nginx_user_id, *nginx_group_id, new_attachment_socket)) {
                    i_socket->closeSocket(new_attachment_socket);
                    new_attachment_socket = -1;

                    nginx_attachment_event.addNetworkingCounter(
                        nginxAttachmentEvent::networkVerdict::REGISTRATION_FAIL
                    );
                    nginx_attachment_event.notify();
                    nginx_attachment_event.resetAllCounters();
                    dbgWarning(D_NGINX_ATTACHMENT) << "Failed to register attachment";
                }
            };
        mainloop->addFileRoutine(
            I_MainLoop::RoutineType::RealTime,
            server_sock,
            accept_attachment_routine,
            "Nginx Attachment registration listener",
            true
        );

        return true;
    }

    Maybe<string>
    getUidFromSocket(I_Socket::socketFd new_attachment_socket)
    {
        dbgAssert(server_sock > 0) << "Registration attempt occurred while registration socket is uninitialized";

        bool did_fail_on_purpose = false;
        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::ReceiveDataFromSocket);
        Maybe<vector<char>> uid_len = i_socket->receiveData(new_attachment_socket, sizeof(uint8_t));
        if (SHOULD_FAIL(
            uid_len.ok(),
            IntentionalFailureHandler::FailureType::ReceiveDataFromSocket,
            &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to read the length of the attachment's UID. Error: "
                << (did_fail_on_purpose ? "Intentional Failure" : uid_len.getErr());
            return genError("Failed to read attachment's UID length");
        }

        uint8_t attachment_uid_len = *reinterpret_cast<const uint8_t *>(uid_len.unpack().data());
        dbgTrace(D_NGINX_ATTACHMENT) << "Attachment's UID length = " << static_cast<int>(attachment_uid_len);
        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::ReceiveDataFromSocket);
        Maybe<vector<char>> attachment_uid = i_socket->receiveData(new_attachment_socket, attachment_uid_len);
        if (SHOULD_FAIL(
            attachment_uid.ok(),
            IntentionalFailureHandler::FailureType::ReceiveDataFromSocket,
            &did_fail_on_purpose
        )) {
            dbgWarning(D_NGINX_ATTACHMENT)
                << "Failed to read the attachment's UID. Error: "
                << (did_fail_on_purpose ? "Intentional Failure" : attachment_uid.getErr());
            return genError("Failed to read the attachment's UID");
        }

        string uid(attachment_uid.unpack().begin(), attachment_uid.unpack().end());
        if (uid != inst_awareness->getUniqueID().unpack()) {
            dbgWarning(D_NGINX_ATTACHMENT) << "NGINX UID is invalid, UID: " << uid;
            return genError("Ivalid UID was sent");
        }
        dbgTrace(D_NGINX_ATTACHMENT) << "Successfully read attachment's UID: " << uid;
        return uid;
    }

    Maybe<uint32_t>
    readIdFromSocket(I_Socket::socketFd new_attachment_socket)
    {
        bool did_fail_on_purpose = false;
        DELAY_IF_NEEDED(IntentionalFailureHandler::FailureType::ReceiveDataFromSocket);
        Maybe<vector<char>> id = i_socket->receiveData(new_attachment_socket, sizeof(uint32_t));
        if (SHOULD_FAIL(
            id.ok(),
            IntentionalFailureHandler::FailureType::ReceiveDataFromSocket,
            &did_fail_on_purpose
        )) {
            return genError(
                string("Failed to read the attachment's User ID or Group ID") +
                (did_fail_on_purpose ? "[Intentional Failure]" : "")
            );
        }

        uint32_t attachment_id = *reinterpret_cast<const uint32_t *>(id.unpack().data());
        dbgTrace(D_NGINX_ATTACHMENT) << "Attachment ID: " << static_cast<int>(attachment_id);
        return attachment_id;
    }

    string static_resources_path;
    FilterVerdict default_verdict;
    FailopenModeListener fail_open_mode_listener;
#ifdef FAILURE_TEST
    IntentionalFailureHandler intentional_failure_handler;
#endif
    CPUMetric nginx_plugin_cpu_metric;

    // Attachment Details
    I_Socket::socketFd server_sock = -1;
    I_Socket::socketFd attachment_sock = -1;

    uint num_of_nginx_ipc_elements = NUM_OF_NGINX_IPC_ELEMENTS;
    uint32_t nginx_worker_user_id = 0;
    uint32_t nginx_worker_group_id = 0;
    string instance_unique_id;
    SharedMemoryIPC *attachment_ipc = nullptr;
    HttpAttachmentConfig attachment_config;
    I_MainLoop::RoutineID attachment_routine_id = 0;
    bool traffic_indicator = false;

    // Interfaces
    I_Socket *i_socket                              = nullptr;
    I_TimeGet *timer                                = nullptr;
    I_MainLoop *mainloop                            = nullptr;
    I_Environment *i_env                            = nullptr;
    I_HttpManager *http_manager                     = nullptr;
    I_InstanceAwareness *inst_awareness             = nullptr;
    I_TableSpecific<SessionID> *i_transaction_table = nullptr;

    // Metrics
    const string default_static_resources_path = DEFAULT_STATIC_RESOURCES_PATH;
    const uint default_metrics_print_interval_sec = 5;
    float metrics_average_table_size    = 0;
    uint64_t metrics_sample_count       = 0;
    uint64_t metrics_max_table_size     = 0;
    uint64_t num_compressed_responses   = 0;
    uint64_t num_uncompressed_responses = 0;
    uint curr_attachment_registrations_counter = 1;
    chrono::time_point<chrono::steady_clock> registration_duration_start = chrono::steady_clock::now();

    chrono::seconds metric_report_interval;
    nginxAttachmentEvent nginx_attachment_event;
    nginxAttachmentMetric nginx_attachment_metric;
    nginxIntakerEvent nginx_intaker_event;
    nginxIntakerMetric nginx_intaker_metric;
    TransactionTableEvent transaction_table_event;
    TransactionTableMetric transaction_table_metric;
};

NginxAttachment::NginxAttachment() : Component("NginxAttachment"), pimpl(make_unique<Impl>()) {}

NginxAttachment::~NginxAttachment() {}

void NginxAttachment::init() { pimpl->init(); }

void NginxAttachment::fini() { pimpl->fini(); }

void
NginxAttachment::preload()
{
    pimpl->preload();
    registerExpectedSetting<string>("agentType");
    registerExpectedConfiguration<bool>("HTTP manager", "Container mode");
    registerExpectedConfiguration<uint>("HTTP manager", "Shared memory segment size in KB");
    registerExpectedConfiguration<string>("HTTP manager", "Nginx permission");
    registerExpectedConfiguration<string>("HTTP manager", "Attachment debug level");
    registerExpectedConfiguration<string>("HTTP manager", "Shared verdict signal path");
    registerExpectedConfiguration<string>("HTTP manager", "Shared settings path");
    registerExpectedConfiguration<string>("HTTP manager", "Max wait time for verdict in sec");
    registerExpectedConfiguration<string>("HTTP manager", "Static resources path");
    registerExpectedConfiguration<bool>("HTTP manager", "Fail Open Mode state");
    registerExpectedConfiguration<uint>("HTTP manager", "Metrics printing interval in sec");
    registerExpectedConfiguration<uint>("HTTP manager", "Keep Alive interval in sec");
    registerExpectedConfiguration<uint>("HTTP manager", "Fail Open timeout msec");
    registerExpectedSetting<DebugConfig>("HTTP manager", "debug context");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX response processing timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX request processing timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX registration thread timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX request header thread timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX request body thread timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX response header thread timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX response body thread timeout msec");
    registerExpectedConfiguration<uint>("HTTP manager", "NGINX inspection mode");
    registerExpectedConfiguration<uint>("Nginx Attachment", "metric reporting interval");
    registerExpectedSetting<bool>("allowOnlyDefinedApplications");
    registerExpectedConfigFile("activeContextConfig", Config::ConfigFileType::Policy);
    registerExpectedConfiguration<UsersAllIdentifiersConfig>("rulebase", "usersIdentifiers");
    BasicRuleConfig::preload();
    WebTriggerConf::preload();
}
