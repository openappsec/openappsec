#include <fstream>
#include <boost/algorithm/string.hpp>
#include <stdlib.h>
#include <arpa/inet.h>

#include "nginx_attachment_util.h"
#include "cptest.h"
#include "c_common/ip_common.h"

using namespace std;
using namespace testing;

class HttpAttachmentUtilTest : public Test
{
public:
    string
    createIPRangesString(const vector<string> &ip_ranges)
    {
        stringstream ip_ranges_string_stream;
        ip_ranges_string_stream << "[";
        for (auto iterator = ip_ranges.begin(); iterator < ip_ranges.end() - 1; iterator++) {
            ip_ranges_string_stream << "\"" << *iterator << "\"" << ", ";
        }
        ip_ranges_string_stream << "\"" << ip_ranges.back() << "\"]";

        return ip_ranges_string_stream.str();
    }

    const string attachment_configuration_file_name = "cp_nano_http_attachment_conf";
    const vector<string> ip_ranges = { "8.8.8.8", "9.9.9.9-10.10.10.10", "0:0:0:0:0:0:0:2-0:0:0:0:0:0:0:5"};
    const string static_resources_path = "/dev/shm/static_resources/";
};

TEST_F(HttpAttachmentUtilTest, GetValidAttachmentConfiguration)
{
    string valid_configuration =
        "{\n"
            "\"context_values\": {"
                "\"clientIp\": \"1.2.3.4\","
                "\"listeningIp\": \"5.6.7.8\","
                "\"uriPrefix\": \"/abc\","
                "\"hostName\": \"test\","
                "\"httpMethod\": \"GET\","
                "\"listeningPort\": 80"
            "},"
            "\"is_fail_open_mode_enabled\": 0,\n"
            "\"fail_open_timeout\": 1234,\n"
            "\"is_fail_open_mode_hold_enabled\": 1,\n"
            "\"fail_open_hold_timeout\": 4321,\n"
            "\"sessions_per_minute_limit_verdict\": \"Accept\",\n"
            "\"max_sessions_per_minute\": 0,\n"
            "\"num_of_nginx_ipc_elements\": 200,\n"
            "\"keep_alive_interval_msec\": 10000,\n"
            "\"dbg_level\": 2,\n"
            "\"nginx_inspection_mode\": 1,\n"
            "\"operation_mode\": 0,\n"
            "\"req_body_thread_timeout_msec\": 155,\n"
            "\"req_proccessing_timeout_msec\": 42,\n"
            "\"registration_thread_timeout_msec\": 101,\n"
            "\"res_proccessing_timeout_msec\": 420,\n"
            "\"res_header_thread_timeout_msec\": 1,\n"
            "\"res_body_thread_timeout_msec\": 0,\n"
            "\"waiting_for_verdict_thread_timeout_msec\": 75,\n"
            "\"req_header_thread_timeout_msec\": 10,\n"
            "\"ip_ranges\": " + createIPRangesString(ip_ranges) + ",\n"
            "\"static_resources_path\": \"" + static_resources_path + "\""
        "}\n";
    ofstream valid_configuration_file(attachment_configuration_file_name);
    valid_configuration_file << valid_configuration;
    valid_configuration_file.close();

    EXPECT_EQ(initAttachmentConfig(attachment_configuration_file_name.c_str()), 1);
    EXPECT_EQ(getDbgLevel(), 2);
    EXPECT_EQ(getStaticResourcesPath(), static_resources_path);
    EXPECT_EQ(isFailOpenMode(), 0);
    EXPECT_EQ(getFailOpenTimeout(), 1234);
    EXPECT_EQ(isFailOpenHoldMode(), 1);
    EXPECT_EQ(getFailOpenHoldTimeout(), 4321);
    EXPECT_EQ(isFailOpenOnSessionLimit(), 1);
    EXPECT_EQ(getMaxSessionsPerMinute(), 0);
    EXPECT_EQ(getNumOfNginxIpcElements(), 200);
    EXPECT_EQ(getKeepAliveIntervalMsec(), 10000);
    EXPECT_EQ(getResProccessingTimeout(), 420);
    EXPECT_EQ(getReqProccessingTimeout(), 42);
    EXPECT_EQ(getRegistrationThreadTimeout(), 101);
    EXPECT_EQ(getReqHeaderThreadTimeout(), 10);
    EXPECT_EQ(getReqBodyThreadTimeout(), 155);
    EXPECT_EQ(getResHeaderThreadTimeout(), 1);
    EXPECT_EQ(getResBodyThreadTimeout(), 0);
    EXPECT_EQ(getWaitingForVerdictThreadTimeout(), 75);
    EXPECT_EQ(getInspectionMode(), ngx_http_inspection_mode::BLOCKING_THREAD);

    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/abc"), 1);
    EXPECT_EQ(isDebugContext("1.2.3.9", "5.6.7.8", 80, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.9", 80, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 88, "GET", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "POST", "test", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "est", "/abc"), 0);
    EXPECT_EQ(isDebugContext("1.2.3.4", "5.6.7.8", 80, "GET", "test", "/ab"), 0);

    EXPECT_EQ(isSkipSource("8.8.8.8"), 1);
    EXPECT_EQ(isSkipSource("8.8.8.9"), 0);
    EXPECT_EQ(isSkipSource("8.8.8.10"), 0);

    EXPECT_EQ(isSkipSource("9.9.9.8"), 0);
    EXPECT_EQ(isSkipSource("9.9.9.9"), 1);
    EXPECT_EQ(isSkipSource("9.255.0.0"), 1);
    EXPECT_EQ(isSkipSource("10.10.10.10"), 1);
    EXPECT_EQ(isSkipSource("10.10.10.11"), 0);

    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:1"), 0);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:2"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:4"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:5"), 1);
    EXPECT_EQ(isSkipSource("0:0:0:0:0:0:0:6"), 0);
}

TEST_F(HttpAttachmentUtilTest, CheckIPAddrValidity)
{
    EXPECT_EQ(isIPAddress("10.0.0.1"), 1);
    EXPECT_EQ(isIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), 1);

    EXPECT_EQ(isIPAddress("333.0.0.1"), 0);
    EXPECT_EQ(isIPAddress("2001:0gb8:85a3:0000:0000:8a2e:0370:7334"), 0);
}
